# 🛡️ 資安弱點動態監控與三階段篩選系統 (Threat-Driven Vulnerability Dashboard)

一個基於 **風險導向弱點治理 (RBVM)** 方法論打造的自動化資安威脅儀表板。本工具即時整合美國 **CISA KEV**、**FIRST.org EPSS** 與 **NVD** 官方情資，透過「三階段篩選機制」協助資安與 IT 維運團隊突破傳統只看 CVSS 分數的盲點，將有限的修補資源精準投入在最危險的漏洞上。

## ✨ 核心功能與三階段篩選邏輯

傳統僅依賴 CVSS 嚴重度（例如 ≥ 9.0 才修補）往往導致嚴重的告警疲勞，因為超過 70% 的高分漏洞從未在真實世界被武器化利用。本系統實作了業界標準的優先級評估模型：

1. **🔴 階段 1：真實攻擊跡象 (`CISA KEV`)**
   * 只要漏洞名列美國 CISA 已知被利用弱點目錄，無視 CVSS 分數，直接判定為 **P0 - Emergency（建議 24–48 小時內修補）**。
2. **🟠 階段 2：未來利用機率預測 (`FIRST.org EPSS`)**
   * 未命中 KEV 但未來 30 天內被利用機率（EPSS）超過設定門檻（預設 ≥ 15%）的漏洞，判定為 **P1 - Critical（建議 7 天內修補）**。
3. **🟡 階段 3：技術嚴重度與資產暴露面 (`NVD CVSS`)**
   * 針對尚未出現公開武器化跡象的漏洞，回歸技術嚴重度評估：
     * **P2 - High（14 天內修補）**：CVSS 達門檻且屬於「對外網際網路公開資產」。
     * **P3 - Medium（30 天內修補）**：CVSS 達門檻但屬於「內部網路資產」。
     * **P4 - Low（可暫緩修補）**：其餘低風險弱點。

### 主要介面模組
* **📖 系統介紹與篩選邏輯**：視覺化說明三階段 RBVM 治理架構與 SLA 建議。
* **🔥 CISA KEV 動態威脅儀表板**：即時連線 CISA 官方 JSON Feed 與 EPSS API，提供 KPI 統計、風險分佈圖表、Top 10 受影響廠商排行與 CSV 報表匯出。
* **📝 自訂/批次輸入 CVE**：支援直接貼上任意文字或掃描報告（自動以正規表達式萃取 CVE 編號），一鍵產出優先級評估報告。

---

## 🚀 快速開始 (Quick Start)

### 1. 下載專案
```bash
git clone [https://github.com/你的帳號/threat-driven-vuln-dashboard.git](https://github.com/你的帳號/threat-driven-vuln-dashboard.git)
cd threat-driven-vuln-dashboard

### 2. 建立虛擬環境並安裝套件
建議使用 Python 3.9 以上版本：
python -m venv venv

# Windows 啟動虛擬環境：
venv\Scripts\activate
# macOS / Linux 啟動虛擬環境：
source venv/bin/activate

# 安裝相依套件
pip install -r requirements.txt

### 3. 設定 API Key（選填，但強烈建議）
CISA KEV 與 FIRST EPSS 皆為完全公開的 API，無需申請金鑰即可使用。

NVD API 若未設定金鑰，每 30 秒僅允許 5 次請求；若您需要在「自訂/批次輸入」中一次查詢大量 CVE，建議至 NVD 官方網站 免費申請 API Key（申請後速率放寬至每 30 秒 50 次）。

您可以透過以下任一方式提供 NVD API Key：

方式 A（透過環境變數，適合本地長期使用）：
cp .env.example .env

打開 .env 檔案，將 your_nvd_api_key_here 替換為您的真實 NVD API Key。

方式 B（透過網頁介面）：
啟動系統後，直接於左側邊欄的「API 密鑰設定」欄位貼上您的 NVD API Key。

### 4. 啟動應用程式
streamlit run app.py

執行後，瀏覽器將自動開啟 http://localhost:8501。

🛡️ 免責聲明與資安提醒
本工具僅供資安防禦、弱點管理評估與學術研究參考，所有弱點情報數據均即時擷取自 CISA、FIRST.org 與 NIST NVD 官方公開介面。
實際修補排程（SLA）仍應依據貴組織內部之業務衝擊分析（BIA）與變更管理規範進行調整。

### 6. 開源授權條款：`LICENSE`

```text
MIT License

Copyright (c) 2026 [wizard828]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
