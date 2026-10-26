//! ESP32 Wi-Fi analyzer.
//!
//! - Runs a WPA2 access point (`AP_SSID` / `AP_PASSWORD`) with a DHCP server at 192.168.4.1.
//! - Periodically scans all channels (AP+STA mode keeps the AP up while scanning).
//! - Promiscuous mode captures beacons, probe/association requests, data and deauth frames
//!   on whatever channel the radio is on (the AP channel, or the channel being scanned).
//! - Serves a web UI at http://192.168.4.1/ and the raw state at /api/state.

#![no_std]
#![no_main]

extern crate alloc;

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::sync::atomic::{AtomicU32, Ordering};

use analyzer_core::{Analyzer, ScanAp};
use embassy_executor::Spawner;
use embassy_net::{
    IpListenEndpoint, Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4, tcp::TcpSocket,
};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use embassy_time::{Duration, Instant, Timer};
use embedded_io_async::Write;
use esp_backtrace as _;
use esp_hal::{clock::CpuClock, ram, rng::Rng, timer::timg::TimerGroup};
use esp_println::println;
use esp_radio::wifi::{
    AuthenticationMethod, AuthenticationMethodConfig, Config, ControllerConfig, Interface,
    SecondaryChannel, WifiController,
    ap::AccessPointConfig,
    scan::{ScanConfig, ScanTypeConfig},
    sniffer::PromiscuousPkt,
    sta::StationConfig,
};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

const AP_SSID: &str = env!("AP_SSID");
const AP_PASSWORD: &str = env!("AP_PASSWORD");
const AP_CHANNEL: u8 = 1;
const GW: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
/// Per-channel dwell of the passive scan. Longer = more frames sniffed per channel,
/// but the AP is off its home channel for that long (>1500 ms drops clients).
const SCAN_DWELL_MS: u64 = 250;
const HTTP_TASKS: usize = 2;

static ANALYZER: Mutex<CriticalSectionRawMutex, Analyzer> = Mutex::new(Analyzer::new());
/// Frames the sniffer could not record because the HTTP task held the table lock.
static DROPPED: AtomicU32 = AtomicU32::new(0);
static INDEX_HTML: &[u8] = include_bytes!("../web/index.html");
/// Primer CSS subset, pre-gzipped by tools/build_primer.py.
static PRIMER_CSS_GZ: &[u8] = include_bytes!("../web/primer.css.gz");

fn now() -> u32 {
    Instant::now().as_secs() as u32
}

#[esp_hal::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    esp_alloc::heap_allocator!(#[ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 72 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // Station side is never connected; it only exists because scanning is unsupported in AP-only mode.
    let wifi_config = Config::AccessPointStation(
        StationConfig::default(),
        AccessPointConfig::default()
            .with_ssid(AP_SSID.try_into().unwrap())
            .with_channel(AP_CHANNEL)
            .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
                AP_PASSWORD.try_into().unwrap(),
            )),
    );
    let ap_device = Interface::access_point();
    let controller = WifiController::new(
        peripherals.WIFI,
        ControllerConfig::default().with_initial_config(wifi_config),
    )
    .unwrap();

    let mut sniffer = controller.sniffer();
    sniffer.set_receive_cb(on_packet);
    sniffer.set_promiscuous_mode(true).unwrap();

    let rng = Rng::new();
    let seed = (rng.random() as u64) << 32 | rng.random() as u64;
    static RESOURCES: StaticCell<StackResources<{ HTTP_TASKS + 2 }>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(
        ap_device,
        embassy_net::Config::ipv4_static(StaticConfigV4 {
            address: Ipv4Cidr::new(GW, 24),
            gateway: Some(GW),
            dns_servers: Default::default(),
        }),
        RESOURCES.init(StackResources::new()),
        seed,
    );

    spawner.spawn(net_task(runner).unwrap());
    spawner.spawn(dhcp_task(stack).unwrap());
    spawner.spawn(scan_task(controller).unwrap());
    for _ in 0..HTTP_TASKS {
        spawner.spawn(http_task(stack).unwrap());
    }

    println!("Join Wi-Fi `{AP_SSID}` and open http://{GW}/");
    // Keep the sniffer alive: dropping it disables promiscuous mode.
    let _sniffer = sniffer;
    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}

/// Runs on the Wi-Fi driver task, so it must not block: frames are dropped while the table is busy.
fn on_packet(p: PromiscuousPkt<'_>) {
    match ANALYZER.try_lock() {
        Ok(mut a) => a.on_frame(p.data, p.rx_cntl.rssi as i8, p.rx_cntl.channel as u8, now()),
        // load+store is enough: only this callback increments it.
        Err(_) => DROPPED.store(DROPPED.load(Ordering::Relaxed) + 1, Ordering::Relaxed),
    }
}

#[embassy_executor::task]
async fn scan_task(mut controller: WifiController<'static>) {
    let config =
        ScanConfig::default()
            .with_show_hidden(true)
            .with_scan_type(ScanTypeConfig::Passive(
                esp_hal::time::Duration::from_millis(SCAN_DWELL_MS),
            ));
    loop {
        match controller.scan_async(&config).await {
            Ok(list) => {
                let t = now();
                let mut a = ANALYZER.lock().await;
                a.counters.scans += 1;
                for ap in &list {
                    a.on_scan(
                        &ScanAp {
                            bssid: ap.bssid,
                            ssid: ap.ssid.as_str(),
                            channel: ap.channel,
                            sec: match ap.secondary_channel {
                                SecondaryChannel::Above => 1,
                                SecondaryChannel::Below => -1,
                                _ => 0,
                            },
                            rssi: ap.signal_strength,
                            auth: auth_name(ap.auth_method),
                        },
                        t,
                    );
                }
            }
            Err(e) => log::warn!("scan failed: {e:?}"),
        }
        Timer::after(Duration::from_secs(1)).await;
    }
}

fn auth_name(m: Option<AuthenticationMethod>) -> &'static str {
    match m {
        Some(AuthenticationMethod::None) => "OPEN",
        Some(AuthenticationMethod::Wep) => "WEP",
        Some(AuthenticationMethod::Wpa) => "WPA",
        Some(AuthenticationMethod::Wpa2Personal) => "WPA2",
        Some(AuthenticationMethod::WpaWpa2Personal) => "WPA/WPA2",
        Some(AuthenticationMethod::Wpa2Enterprise) => "WPA2-EAP",
        Some(AuthenticationMethod::Wpa3Personal) => "WPA3",
        Some(AuthenticationMethod::Wpa2Wpa3Personal) => "WPA2/WPA3",
        Some(AuthenticationMethod::Owe) => "OWE",
        Some(_) => "OTHER",
        None => "?",
    }
}

#[embassy_executor::task(pool_size = HTTP_TASKS)]
async fn http_task(stack: Stack<'static>) {
    let mut rx = [0u8; 1024];
    let mut tx = [0u8; 2048];
    let mut req = [0u8; 512];
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_timeout(Some(Duration::from_secs(5)));
        if socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 80,
            })
            .await
            .is_err()
        {
            continue;
        }
        // Only the request line matters; headers beyond the buffer are ignored.
        let mut n = 0;
        while n < req.len() {
            match socket.read(&mut req[n..]).await {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
            if req[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let line = req[..n].split(|&b| b == b'\r').next().unwrap_or(&[]);
        let mut parts = line.split(|&b| b == b' ');
        let (method, path) = (parts.next().unwrap_or(&[]), parts.next().unwrap_or(&[]));
        let _ = respond(&mut socket, method, path).await;
        let _ = socket.flush().await;
        socket.close();
        Timer::after(Duration::from_millis(50)).await;
        socket.abort();
    }
}

async fn respond(
    s: &mut TcpSocket<'_>,
    method: &[u8],
    path: &[u8],
) -> Result<(), embassy_net::tcp::Error> {
    match (method, path) {
        (b"GET", b"/") | (b"GET", b"/index.html") => {
            send(s, "200 OK", "text/html; charset=utf-8", "", INDEX_HTML).await
        }
        (b"GET", b"/primer.css") => {
            let extra = "Content-Encoding: gzip\r\nCache-Control: max-age=86400\r\n";
            send(s, "200 OK", "text/css", extra, PRIMER_CSS_GZ).await
        }
        (b"GET", b"/api/state") => {
            // Serialize under the lock but send after releasing it, so the sniffer is blocked only briefly.
            let body = {
                let mut a = ANALYZER.lock().await;
                a.now = now();
                a.counters.dropped = DROPPED.load(Ordering::Relaxed);
                // Worst case is ~30 KB (see analyzer-core's size test), ~48 KB peak while the Vec grows.
                serde_json::to_vec(&*a)
            };
            match body {
                Ok(b) => send(s, "200 OK", "application/json", NO_STORE, &b).await,
                Err(_) => {
                    send(
                        s,
                        "500 Internal Server Error",
                        "text/plain",
                        NO_STORE,
                        b"serialize failed",
                    )
                    .await
                }
            }
        }
        (b"POST", b"/api/reset") => {
            ANALYZER.lock().await.clear();
            DROPPED.store(0, Ordering::Relaxed);
            send(s, "200 OK", "text/plain", NO_STORE, b"ok").await
        }
        _ => send(s, "404 Not Found", "text/plain", NO_STORE, b"not found").await,
    }
}

const NO_STORE: &str = "Cache-Control: no-store\r\n";

/// `extra` is zero or more complete header lines, each ending in CRLF.
async fn send(
    s: &mut TcpSocket<'_>,
    status: &str,
    ctype: &str,
    extra: &str,
    body: &[u8],
) -> Result<(), embassy_net::tcp::Error> {
    let head = alloc::format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface>) {
    runner.run().await
}

#[embassy_executor::task]
async fn dhcp_task(stack: Stack<'static>) {
    use edge_dhcp::{
        io::{self, DEFAULT_SERVER_PORT},
        server::{Server, ServerOptions},
    };
    use edge_nal::UdpBind;
    use edge_nal_embassy::{Udp, UdpBuffers};

    let mut buf = [0u8; 1500];
    // No gateway / DNS is offered, so the Mac keeps its other routes (e.g. Ethernet) for internet.
    let buffers = UdpBuffers::<1, 1024, 1024, 4>::new();
    let udp = Udp::new(stack, &buffers);
    let mut socket = udp
        .bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            DEFAULT_SERVER_PORT,
        )))
        .await
        .unwrap();
    loop {
        let _ = io::server::run(
            &mut Server::<_, 16>::new_with_et(GW),
            &ServerOptions::new(GW, None),
            &mut socket,
            &mut buf,
        )
        .await
        .inspect_err(|e| log::warn!("DHCP server error: {e:?}"));
        Timer::after(Duration::from_millis(500)).await;
    }
}
