//! Chip-independent Wi-Fi analysis: parses raw 802.11 frames and scan results
//! into AP / client / channel tables. No hardware deps, so it is tested on the host.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use serde::Serialize;

pub const MAX_APS: usize = 64;
pub const MAX_CLIENTS: usize = 48;
pub const MAX_PROBES: usize = 5;
pub const MAX_DEAUTHS: usize = 32;
/// Index 0 is unused so that `channels[ch]` matches the channel number (1..=14).
pub const CHANNELS: usize = 15;

pub type Mac = [u8; 6];

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Ap {
    pub bssid: Mac,
    pub ssid: String,
    pub channel: u8,
    /// 20 or 40 MHz.
    pub width: u8,
    /// +1 = secondary channel above, -1 = below, 0 = none.
    pub sec: i8,
    pub rssi: i8,
    pub auth: &'static str,
    pub beacons: u32,
    pub first_seen: u32,
    pub last_seen: u32,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Client {
    pub mac: Mac,
    /// BSSID the client is exchanging data with / associating to.
    pub bssid: Option<Mac>,
    pub rssi: i8,
    /// SSIDs from probe and (re)association requests, i.e. networks the client looks for.
    pub probes: Vec<String>,
    pub frames: u32,
    pub first_seen: u32,
    pub last_seen: u32,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Deauth {
    pub time: u32,
    /// "deauth" or "disassoc".
    pub kind: &'static str,
    pub src: Mac,
    pub dst: Mac,
    pub bssid: Mac,
    pub reason: u16,
    pub channel: u8,
    pub rssi: i8,
}

#[derive(Serialize, Clone, Copy, Default, Debug, PartialEq)]
pub struct ChannelStats {
    pub frames: u32,
    pub mgmt: u32,
    pub data: u32,
    /// Sum of RSSI for mean calculation in the UI.
    pub rssi_sum: i64,
}

#[derive(Serialize, Default, Debug)]
pub struct Counters {
    pub frames: u32,
    pub mgmt: u32,
    pub ctrl: u32,
    pub data: u32,
    pub beacons: u32,
    pub probes: u32,
    pub deauths: u32,
    pub scans: u32,
    /// Frames lost because the table was locked (e.g. while serving HTTP).
    pub dropped: u32,
}

#[derive(Serialize, Debug)]
pub struct Analyzer {
    pub now: u32,
    pub aps: Vec<Ap>,
    pub clients: Vec<Client>,
    pub deauths: Vec<Deauth>,
    pub channels: [ChannelStats; CHANNELS],
    pub counters: Counters,
}

/// One AP from an active/passive scan (`esp_wifi_scan`), already converted to plain types.
pub struct ScanAp<'a> {
    pub bssid: Mac,
    pub ssid: &'a str,
    pub channel: u8,
    pub sec: i8,
    pub rssi: i8,
    pub auth: &'static str,
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer {
    pub const fn new() -> Self {
        Self {
            now: 0,
            aps: Vec::new(),
            clients: Vec::new(),
            deauths: Vec::new(),
            channels: [ChannelStats {
                frames: 0,
                mgmt: 0,
                data: 0,
                rssi_sum: 0,
            }; CHANNELS],
            counters: Counters {
                frames: 0,
                mgmt: 0,
                ctrl: 0,
                data: 0,
                beacons: 0,
                probes: 0,
                deauths: 0,
                scans: 0,
                dropped: 0,
            },
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn on_scan(&mut self, s: &ScanAp, now: u32) {
        self.now = now;
        let ap = upsert_ap(&mut self.aps, s.bssid, now);
        if !s.ssid.is_empty() {
            ap.ssid = s.ssid.into();
        }
        ap.channel = s.channel;
        ap.sec = s.sec;
        ap.width = if s.sec == 0 { 20 } else { 40 };
        ap.rssi = s.rssi;
        ap.auth = s.auth;
    }

    /// `data` is the raw 802.11 frame starting at Frame Control (FCS may be appended).
    pub fn on_frame(&mut self, data: &[u8], rssi: i8, channel: u8, now: u32) {
        self.now = now;
        self.counters.frames += 1;
        let ch = &mut self.channels[(channel as usize).min(CHANNELS - 1)];
        ch.frames += 1;
        ch.rssi_sum += rssi as i64;
        if data.len() < 2 {
            return;
        }
        let ftype = (data[0] >> 2) & 3;
        let subtype = data[0] >> 4;
        match ftype {
            0 => {
                self.counters.mgmt += 1;
                ch.mgmt += 1;
                if data.len() >= 24 {
                    self.on_mgmt(subtype, data, rssi, channel, now);
                }
            }
            1 => self.counters.ctrl += 1,
            2 => {
                self.counters.data += 1;
                ch.data += 1;
                if data.len() >= 24 {
                    self.on_data(data, rssi, now);
                }
            }
            _ => {}
        }
    }

    fn on_mgmt(&mut self, subtype: u8, f: &[u8], rssi: i8, channel: u8, now: u32) {
        let da = mac(&f[4..10]);
        let sa = mac(&f[10..16]);
        let bssid = mac(&f[16..22]);
        match subtype {
            // beacon, probe response: fixed params (timestamp 8, interval 2, capability 2) then IEs
            8 | 5 if f.len() >= 36 => {
                if subtype == 8 {
                    self.counters.beacons += 1;
                }
                let cap = u16::from_le_bytes([f[34], f[35]]);
                let ies = parse_ies(&f[36..]);
                let ap = upsert_ap(&mut self.aps, bssid, now);
                if subtype == 8 {
                    ap.beacons += 1;
                }
                // Hidden networks beacon an empty or zero-filled SSID; keep a name learned
                // from a probe response instead of overwriting it.
                if let Some(ssid) = ies.ssid.filter(|s| s.iter().any(|&b| b != 0)) {
                    ap.ssid = String::from_utf8_lossy(ssid).into();
                }
                ap.channel = ies.channel.unwrap_or(channel);
                ap.sec = ies.sec;
                ap.width = if ies.sec == 0 { 20 } else { 40 };
                ap.rssi = rssi;
                ap.auth = auth_name(cap, &ies);
            }
            // probe request: IEs start right after the header
            4 => {
                self.counters.probes += 1;
                let ies = parse_ies(&f[24..]);
                let c = self.client(sa, now);
                c.rssi = rssi;
                if let Some(ssid) = ies.ssid.filter(|s| !s.is_empty()) {
                    add_probe(c, ssid);
                }
            }
            // (re)association request: capability 2 + listen interval 2 (+ current AP 6 for reassoc)
            0 | 2 => {
                let off = if subtype == 0 { 28 } else { 34 };
                let ies = parse_ies(f.get(off..).unwrap_or(&[]));
                let c = self.client(sa, now);
                c.rssi = rssi;
                c.bssid = Some(bssid);
                if let Some(ssid) = ies.ssid.filter(|s| !s.is_empty()) {
                    add_probe(c, ssid);
                }
            }
            // disassociation (10), deauthentication (12)
            10 | 12 => {
                self.counters.deauths += 1;
                if self.deauths.len() >= MAX_DEAUTHS {
                    self.deauths.remove(0);
                }
                self.deauths.push(Deauth {
                    time: now,
                    kind: if subtype == 12 { "deauth" } else { "disassoc" },
                    src: sa,
                    dst: da,
                    bssid,
                    reason: f
                        .get(24..26)
                        .map_or(0, |r| u16::from_le_bytes([r[0], r[1]])),
                    channel,
                    rssi,
                });
            }
            _ => {}
        }
    }

    fn on_data(&mut self, f: &[u8], rssi: i8, now: u32) {
        let a1 = mac(&f[4..10]);
        let a2 = mac(&f[10..16]);
        let a3 = mac(&f[16..22]);
        // Only frames sent *by* the client give a reliable RSSI for it.
        let (client, bssid, from_client) = match f[1] & 3 {
            0b01 => (a2, a1, true),  // to DS: client -> AP
            0b10 => (a1, a2, false), // from DS: AP -> client
            0b00 => (a2, a3, true),  // IBSS / direct link
            _ => return,             // WDS: no single client
        };
        if is_group(&client) || client == bssid {
            return;
        }
        let c = self.client(client, now);
        c.bssid = Some(bssid);
        if from_client {
            c.rssi = rssi;
        }
    }

    fn client(&mut self, mac: Mac, now: u32) -> &mut Client {
        let i = match self.clients.iter().position(|c| c.mac == mac) {
            Some(i) => i,
            None => {
                let new = Client {
                    mac,
                    bssid: None,
                    rssi: -127,
                    probes: Vec::new(),
                    frames: 0,
                    first_seen: now,
                    last_seen: now,
                };
                insert_evicting(&mut self.clients, new, MAX_CLIENTS, |c| c.last_seen)
            }
        };
        let c = &mut self.clients[i];
        c.frames += 1;
        c.last_seen = now;
        c
    }
}

fn upsert_ap(aps: &mut Vec<Ap>, bssid: Mac, now: u32) -> &mut Ap {
    let i = match aps.iter().position(|a| a.bssid == bssid) {
        Some(i) => i,
        None => {
            let new = Ap {
                bssid,
                ssid: String::new(),
                channel: 0,
                width: 20,
                sec: 0,
                rssi: -127,
                auth: "?",
                beacons: 0,
                first_seen: now,
                last_seen: now,
            };
            insert_evicting(aps, new, MAX_APS, |a| a.last_seen)
        }
    };
    aps[i].last_seen = now;
    &mut aps[i]
}

/// Pushes `item`, replacing the least recently seen entry when `max` is reached. Returns its index.
fn insert_evicting<T>(v: &mut Vec<T>, item: T, max: usize, seen: impl Fn(&T) -> u32) -> usize {
    if v.len() < max {
        v.push(item);
        return v.len() - 1;
    }
    let (i, _) = v.iter().enumerate().min_by_key(|(_, x)| seen(x)).unwrap();
    v[i] = item;
    i
}

fn add_probe(c: &mut Client, ssid: &[u8]) {
    let s: String = String::from_utf8_lossy(ssid).into();
    if c.probes.contains(&s) {
        return;
    }
    if c.probes.len() >= MAX_PROBES {
        c.probes.remove(0);
    }
    c.probes.push(s);
}

fn mac(b: &[u8]) -> Mac {
    b.try_into().unwrap()
}

/// Multicast/broadcast addresses have the I/G bit set.
fn is_group(m: &Mac) -> bool {
    m[0] & 1 != 0
}

#[derive(Default, Debug)]
struct Ies<'a> {
    ssid: Option<&'a [u8]>,
    channel: Option<u8>,
    sec: i8,
    rsn: Option<&'a [u8]>,
    wpa: bool,
}

fn parse_ies(mut b: &[u8]) -> Ies<'_> {
    let mut ies = Ies::default();
    while b.len() >= 2 {
        let (id, len) = (b[0], b[1] as usize);
        let Some(body) = b.get(2..2 + len) else { break };
        match id {
            0 if len <= 32 => ies.ssid = Some(body),
            3 if len == 1 => ies.channel = Some(body[0]),
            // HT Operation: byte 1 bits 0-1 = secondary channel offset (1 above, 3 below)
            61 if len >= 2 => {
                ies.sec = match body[1] & 3 {
                    1 => 1,
                    3 => -1,
                    _ => 0,
                }
            }
            48 => ies.rsn = Some(body),
            // Microsoft WPA vendor IE: OUI 00:50:F2, type 1
            221 if body.starts_with(&[0x00, 0x50, 0xf2, 0x01]) => ies.wpa = true,
            _ => {}
        }
        b = &b[2 + len..];
    }
    ies
}

fn auth_name(cap: u16, ies: &Ies) -> &'static str {
    if let Some(rsn) = ies.rsn {
        // RSN: version 2, group cipher 4, pairwise count 2 + 4n, AKM count 2 + 4n
        let mut psk = false;
        let mut sae = false;
        let mut eap = false;
        if let Some(pc) = rsn
            .get(6..8)
            .map(|c| u16::from_le_bytes([c[0], c[1]]) as usize)
        {
            let akm_at = 8 + 4 * pc;
            if let Some(ac) = rsn.get(akm_at..akm_at + 2) {
                let n = u16::from_le_bytes([ac[0], ac[1]]) as usize;
                for k in 0..n {
                    let Some(s) = rsn.get(akm_at + 2 + 4 * k..akm_at + 6 + 4 * k) else {
                        break;
                    };
                    match s[3] {
                        1 | 5 => eap = true,
                        2 | 6 => psk = true,
                        8 | 9 => sae = true,
                        _ => {}
                    }
                }
            }
        }
        return match (eap, psk, sae) {
            (true, _, _) => "WPA2-EAP",
            (_, true, true) => "WPA2/WPA3",
            (_, _, true) => "WPA3",
            _ if ies.wpa => "WPA/WPA2",
            _ => "WPA2",
        };
    }
    if ies.wpa {
        "WPA"
    } else if cap & 0x0010 != 0 {
        "WEP"
    } else {
        "OPEN"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: Mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const STA: Mac = [0xa4, 0x83, 0xe7, 0x01, 0x02, 0x03];
    const BCAST: Mac = [0xff; 6];

    fn hdr(fc0: u8, fc1: u8, a1: Mac, a2: Mac, a3: Mac) -> Vec<u8> {
        let mut f = vec![fc0, fc1, 0, 0];
        f.extend_from_slice(&a1);
        f.extend_from_slice(&a2);
        f.extend_from_slice(&a3);
        f.extend_from_slice(&[0, 0]); // sequence control
        f
    }

    fn ie(id: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![id, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    fn beacon(ssid: &[u8], ch: u8, cap: u16, extra: &[u8]) -> Vec<u8> {
        let mut f = hdr(0x80, 0, BCAST, AP, AP);
        f.extend_from_slice(&[0; 10]); // timestamp + interval
        f.extend_from_slice(&cap.to_le_bytes());
        f.extend(ie(0, ssid));
        f.extend(ie(3, &[ch]));
        f.extend_from_slice(extra);
        f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // FCS
        f
    }

    fn rsn(akms: &[u8]) -> Vec<u8> {
        let mut b = vec![1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4];
        b.extend_from_slice(&(akms.len() as u16).to_le_bytes());
        for &a in akms {
            b.extend_from_slice(&[0x00, 0x0f, 0xac, a]);
        }
        b.extend_from_slice(&[0, 0]);
        ie(48, &b)
    }

    #[test]
    fn beacon_creates_ap_with_security_and_width() {
        let mut a = Analyzer::new();
        let mut extra = rsn(&[2, 8]);
        extra.extend(ie(61, &[6, 1, 0, 0, 0]));
        a.on_frame(&beacon(b"home", 6, 0x0011, &extra), -40, 5, 10);
        assert_eq!(a.aps.len(), 1);
        let ap = &a.aps[0];
        assert_eq!(
            (ap.ssid.as_str(), ap.channel, ap.width, ap.sec),
            ("home", 6, 40, 1)
        );
        assert_eq!((ap.auth, ap.rssi, ap.beacons), ("WPA2/WPA3", -40, 1));
        assert_eq!((a.counters.beacons, a.channels[5].mgmt), (1, 1));
    }

    #[test]
    fn auth_variants() {
        let mut a = Analyzer::new();
        a.on_frame(&beacon(b"o", 1, 0x0001, &[]), -50, 1, 0);
        assert_eq!(a.aps[0].auth, "OPEN");
        a.on_frame(&beacon(b"w", 1, 0x0011, &[]), -50, 1, 0);
        assert_eq!(a.aps[0].auth, "WEP");
        a.on_frame(&beacon(b"e", 1, 0x0011, &rsn(&[1])), -50, 1, 0);
        assert_eq!(a.aps[0].auth, "WPA2-EAP");
        a.on_frame(&beacon(b"p", 1, 0x0011, &rsn(&[2])), -50, 1, 0);
        assert_eq!(a.aps[0].auth, "WPA2");
        a.on_frame(&beacon(b"s", 1, 0x0011, &rsn(&[8])), -50, 1, 0);
        assert_eq!(a.aps[0].auth, "WPA3");
    }

    #[test]
    fn hidden_ssid_keeps_known_name() {
        let mut a = Analyzer::new();
        a.on_frame(&beacon(b"secret", 1, 0, &[]), -50, 1, 0);
        a.on_frame(&beacon(&[0, 0, 0], 1, 0, &[]), -50, 1, 1);
        assert_eq!(a.aps[0].ssid, "secret");
        assert_eq!(a.aps[0].beacons, 2);
    }

    #[test]
    fn probe_request_records_ssids_deduped() {
        let mut a = Analyzer::new();
        let mut f = hdr(0x40, 0, BCAST, STA, BCAST);
        f.extend(ie(0, b"cafe-wifi"));
        a.on_frame(&f, -60, 1, 3);
        a.on_frame(&f, -61, 1, 4);
        let mut wild = hdr(0x40, 0, BCAST, STA, BCAST);
        wild.extend(ie(0, b""));
        a.on_frame(&wild, -62, 1, 5);
        assert_eq!(a.clients.len(), 1);
        let c = &a.clients[0];
        assert_eq!(c.probes, vec!["cafe-wifi".to_string()]);
        assert_eq!(
            (c.frames, c.rssi, c.last_seen, c.first_seen),
            (3, -62, 5, 3)
        );
    }

    #[test]
    fn assoc_request_links_client_to_bssid_and_ssid() {
        let mut a = Analyzer::new();
        let mut f = hdr(0x00, 0, AP, STA, AP);
        f.extend_from_slice(&[0x11, 0, 0x0a, 0]); // capability, listen interval
        f.extend(ie(0, b"office"));
        a.on_frame(&f, -55, 11, 0);
        assert_eq!(a.clients[0].bssid, Some(AP));
        assert_eq!(a.clients[0].probes, vec!["office".to_string()]);
    }

    #[test]
    fn data_frames_map_client_to_ap_both_directions() {
        let mut a = Analyzer::new();
        a.on_frame(&hdr(0x08, 0x01, AP, STA, BCAST), -45, 6, 0); // to DS
        assert_eq!(a.clients[0].bssid, Some(AP));
        assert_eq!(a.clients[0].mac, STA);
        let other: Mac = [0x10, 0, 0, 0, 0, 1];
        a.on_frame(&hdr(0x08, 0x02, other, AP, AP), -30, 6, 1); // from DS
        assert_eq!(a.clients.len(), 2);
        // multicast destination from AP is not a client
        a.on_frame(&hdr(0x08, 0x02, BCAST, AP, AP), -30, 6, 2);
        assert_eq!(a.clients.len(), 2);
        assert_eq!(a.counters.data, 3);
    }

    #[test]
    fn deauth_is_logged_with_reason_and_capped() {
        let mut a = Analyzer::new();
        let mut f = hdr(0xc0, 0, STA, AP, AP);
        f.extend_from_slice(&7u16.to_le_bytes());
        for t in 0..(MAX_DEAUTHS as u32 + 5) {
            a.on_frame(&f, -20, 1, t);
        }
        assert_eq!(a.deauths.len(), MAX_DEAUTHS);
        assert_eq!(a.deauths[0].time, 5);
        assert_eq!((a.deauths[0].reason, a.deauths[0].kind), (7, "deauth"));
        assert_eq!(a.counters.deauths, MAX_DEAUTHS as u32 + 5);
    }

    #[test]
    fn tables_evict_least_recently_seen() {
        let mut a = Analyzer::new();
        for i in 0..MAX_APS as u32 + 1 {
            let s = ScanAp {
                bssid: [0, 0, 0, 0, 0, i as u8],
                ssid: "x",
                channel: 1,
                sec: 0,
                rssi: -50,
                auth: "OPEN",
            };
            a.on_scan(&s, i);
        }
        assert_eq!(a.aps.len(), MAX_APS);
        assert!(!a.aps.iter().any(|ap| ap.bssid[5] == 0));
    }

    #[test]
    fn truncated_frames_do_not_panic() {
        let mut a = Analyzer::new();
        let full = beacon(b"home", 6, 0x0011, &rsn(&[2]));
        for n in 0..full.len() {
            a.on_frame(&full[..n], -50, 99, 0);
        }
        for fc in [0x40u8, 0x00, 0x20, 0xc0, 0xa0, 0x08, 0x50] {
            let f = hdr(fc, 1, AP, STA, AP);
            for n in 0..f.len() + 3 {
                let mut g = f.clone();
                g.resize(n, 0xff);
                a.on_frame(&g, -50, 1, 0);
            }
        }
        // out-of-range channel is clamped into the last slot
        assert!(a.channels[CHANNELS - 1].frames > 0);
    }

    #[test]
    fn serializes_to_json() {
        let mut a = Analyzer::new();
        a.on_frame(&beacon(b"q\"<x>", 1, 0, &[]), -50, 1, 0);
        let j = serde_json::to_string(&a).unwrap();
        assert!(j.contains(r#""ssid":"q\"<x>""#), "{j}");
    }
}

#[cfg(test)]
mod size {
    use super::*;
    #[test]
    fn worst_case_json_size() {
        let mut a = Analyzer::new();
        let ssid = "\u{7121}".repeat(10); // 30 UTF-8 bytes
        for i in 0..MAX_APS as u8 {
            a.on_scan(
                &ScanAp {
                    bssid: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, i],
                    ssid: &ssid,
                    channel: 11,
                    sec: -1,
                    rssi: -100,
                    auth: "WPA2/WPA3",
                },
                4_000_000_000,
            );
        }
        for i in 0..MAX_CLIENTS as u8 {
            let mut f = vec![0x40, 0, 0, 0];
            f.extend_from_slice(&[0xff; 6]);
            f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, i]);
            f.extend_from_slice(&[0xff; 8]);
            for p in 0..MAX_PROBES as u8 {
                let mut g = f.clone();
                g.push(0);
                g.push(32);
                g.extend_from_slice(&[b'a' + p; 32]);
                a.on_frame(&g, -100, 11, 4_000_000_000);
            }
        }
        let n = serde_json::to_vec(&a).unwrap().len();
        println!("worst-case JSON: {n} bytes");
        // Must stay well under the firmware heap (see firmware/src/main.rs).
        assert!(n < 32 * 1024);
    }
}
