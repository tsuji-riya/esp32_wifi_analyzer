# esp32_wifi_analyzer

無印 ESP32 と esp-rs（`no_std`: esp-hal / esp-radio / embassy）で作る Wi-Fi アナライザです。
ESP32 が自分のアクセスポイントを立て、Mac からそこに接続してブラウザで解析結果を見ます。
Web UI は [GitHub Primer CSS](https://primer.style/css) で作っています。

## 機能

| タブ | 内容 |
|---|---|
| チャンネル | 2.4 GHz のチャンネルマップ（AP ごとの占有帯域と RSSI、40 MHz 対応）、チャンネル別の干渉スコアと受信フレーム数、1/6/11 の中で最も空いている推奨チャンネル、★ を付けた AP の RSSI 推移（直近 5 分） |
| アクセスポイント | SSID / BSSID / チャンネル / 帯域幅 / RSSI / セキュリティ（OPEN・WEP・WPA〜WPA3・Enterprise）/ 接続クライアント数 / ビーコン数。ソートと絞り込みができます |
| クライアント | 端末 MAC（ランダム MAC 判定つき）、**接続先 SSID / BSSID**、RSSI、端末が**探している SSID**（プローブ要求とアソシエーション要求から取得） |
| 探索 SSID | 端末が探している SSID の集計（何台が探しているか、付近に同名 AP があるか） |
| Deauth | Deauthentication / Disassociation フレームの記録（理由コードつき）。30 秒で 10 件以上あると警告を出します |

ほかに、JSON エクスポート、一時停止、リセット、ダークモード（OS 設定に追従）にも対応しています。

## 仕組み

- AP+STA モードで動かします。STA 側はどこにも接続せず、スキャンのためだけに使います（AP 単独モードではスキャンできないため）。
- 約 1 秒おきにパッシブスキャンします（1 チャンネルあたり 250 ms）。スキャン中はスキャン対象のチャンネルに無線が移るので、プロミスキャスモードで捕まえるフレームも全チャンネル分になる設計です（実際に巡回できているかは、チャンネル混雑度グラフのチャンネル別フレーム数で確認できます）。
- 802.11 フレームの解析は `core/`（ハードウェア非依存のクレート）で行い、ホスト PC 上でユニットテストしています。

```
core/      フレーム解析と AP/クライアント/チャンネル表（no_std、ホストでテスト可能）
firmware/  ESP32 ファームウェア（AP, DHCP, スキャン, スニファ, HTTP サーバー）
  web/     index.html と Primer CSS のサブセット（gzip 済み）
tools/     Primer CSS サブセットを作るスクリプト
```

## ビルドと書き込み

[espup](https://github.com/esp-rs/espup) で Xtensa 用の Rust ツールチェーンを入れ、[espflash](https://github.com/esp-rs/espflash) を用意します。

```sh
cargo install espup espflash --locked
espup install                 # toolchain "esp" と xtensa-esp-elf GCC を入れる
. ~/export-esp.sh             # PATH を通す（シェルを開くたびに必要）

cd firmware
AP_SSID=my-analyzer AP_PASSWORD='8文字以上のパスワード' cargo run --release   # ビルド・書き込み・シリアルモニタ
```

`AP_SSID` と `AP_PASSWORD` を指定しないと、`esp32-analyzer` / `analyzer1234` になります。共有の場所で使う場合は必ず変更してください。

## Mac からの使い方

1. Wi-Fi メニューから `AP_SSID` に接続します（DHCP で 192.168.4.x が割り当てられます）。
2. ブラウザで <http://192.168.4.1/> を開きます。
3. この AP はインターネットに出られません。DHCP でゲートウェイと DNS を配らないので、有線 LAN などを併用していればインターネットはそちらを通ります。

`GET /api/state` で生の JSON、`POST /api/reset` で表のリセットもできます。

## テスト

```sh
cd core && cargo test   # フレーム解析のユニットテスト（ホストで実行）
```

## 制約と注意

- ESP32 は 2.4 GHz 専用なので、5 GHz の AP や端末は見えません。
- スニファで拾えるのは、その時点で無線がいるチャンネルのフレームだけです。チャンネルを巡回するので取りこぼしがあり、AP の待受チャンネル（ch 1）は受信フレーム数が多めに出ます。
- スキャンで AP の待受チャンネルを離れている間（最大 250 ms）、Mac の通信は止まります。Web UI は 2 秒おきの取得なので、大きな影響は出ない想定です。
- 表の上限は AP 64 件、クライアント 48 件、探索 SSID は 1 台あたり 5 件、Deauth は 32 件です。上限に達すると、最後に見えた時刻が最も古いものから入れ替えます。
- 最近の iPhone / Android / macOS はプローブ要求にランダム MAC を使い、SSID を含めないことも多いので、「探索 SSID」は端末によっては空になります。
- 自分の管理下にあるネットワーク、または許可を得たネットワークでのみ使ってください。

## Primer CSS を更新する場合

```sh
npm pack @primer/css@21.5.1 && tar -xzf primer-css-21.5.1.tgz
python3 tools/build_primer.py package/dist
```

v22 以降では Label / flash / UnderlineNav などのクラスが削除されているため、v21 系を使っています。
Primer CSS のライセンスは MIT です（`firmware/web/primer-LICENSE`）。
