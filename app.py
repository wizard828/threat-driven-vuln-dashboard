import os
import re
import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv
from streamlit_autorefresh import st_autorefresh

# 載入本地端 .env 檔案中的環境變數（若無 .env 檔也不會報錯）
load_dotenv()

# ------------------------------------------------------------------
# 頁面基本設定
# ------------------------------------------------------------------
st.set_page_config(
    page_title="資安弱點動態監控系統",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ 資安弱點動態監控與三階段篩選系統")
st.caption("即時連線 CISA KEV、FIRST.org EPSS 與 NVD 官方資料庫，實踐風險導向弱點治理 (RBVM)")

# ------------------------------------------------------------------
# 側邊欄設定
# ------------------------------------------------------------------
st.sidebar.header("⚙️ 篩選門檻設定")
epss_threshold = st.sidebar.slider("EPSS 警戒門檻 (%)", 1, 50, 15) / 100.0
cvss_threshold = st.sidebar.slider("CVSS 嚴重度門檻", 1.0, 10.0, 7.0)

st.sidebar.divider()
st.sidebar.header("🔑 API 密鑰設定")

# 優先從環境變數讀取 NVD_API_KEY，若無則留空讓使用者於介面輸入
default_nvd_key = os.getenv("NVD_API_KEY", "")
nvd_api_key = st.sidebar.text_input(
    "NVD API Key (選填)",
    value=default_nvd_key,
    type="password",
    help="若未填寫 NVD API Key，每 30 秒僅能查詢 5 次；填寫後速率限制放寬至 50 次。"
)

if nvd_api_key:
    st.sidebar.success("✅ 已載入 NVD API Key（高速查詢模式）")
else:
    st.sidebar.warning("⚠️ 未設定 NVD API Key（受限於公開查詢速率）")

st.sidebar.divider()
st.sidebar.header("🔄 即時更新設定")
auto_refresh = st.sidebar.checkbox("啟用自動更新 (每 60 秒)")

# 使用非阻塞式的自動刷新（不會卡死 UI 執行緒）
if auto_refresh:
    st_autorefresh(interval=60 * 1000, key="vulnerability_monitor_counter")

# ------------------------------------------------------------------
# 資料抓取與快取 API 模組
# ------------------------------------------------------------------
@st.cache_data(ttl=3600)
def get_cisa_kev():
    """取得美國 CISA 已知被利用弱點 (KEV) 清單，快取 1 小時"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        data = res.json().get('vulnerabilities', [])
        return {item['cveID']: item for item in data}
    except Exception as e:
        st.error(f"CISA KEV 連線失敗: {e}")
    return {}

def fetch_epss_scores(cve_list):
    """批次向 FIRST.org 查詢 CVE 的 EPSS 利用機率"""
    epss_map = {}
    if not cve_list:
        return epss_map
    
    chunk_size = 50
    for i in range(0, len(cve_list), chunk_size):
        chunk = cve_list[i:i + chunk_size]
        url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
        try:
            res = requests.get(url, timeout=10)
            res.raise_for_status()
            for item in res.json().get('data', []):
                epss_map[item['cve']] = float(item['epss'])
        except Exception as e:
            st.warning(f"EPSS 批次查詢部分失敗 ({len(chunk)} 個 CVE): {e}")
    return epss_map

@st.cache_data(ttl=86400)
def get_nvd_cvss(cve_id, api_key=""):
    """向 NVD 查詢單一 CVE 的 CVSS 基礎分數，快取 24 小時"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key} if api_key else {}
        
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                metrics = vulnerabilities[0].get('cve', {}).get('metrics', {})
                for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if key in metrics and metrics[key]:
                        return float(metrics[key][0]['cvssData']['baseScore'])
    except Exception:
        pass
    return None

cisa_kev_dict = get_cisa_kev()

# ------------------------------------------------------------------
# 介面分頁設計
# ------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs([
    "📖 系統介紹與篩選邏輯",
    "🔥 CISA KEV 動態威脅儀表板",
    "📝 自訂/批次輸入 CVE"
])

# ==================== TAB 1: 系統介紹與篩選邏輯 ====================
with tab1:
    st.subheader("📖 威脅驅動弱點優先級治理 (Threat-Informed Vulnerability Management)")
    st.markdown("""
    在現代資安維運 (SOC) 中，傳統僅靠 CVSS 分數（如 CVSS > 9 才修補）的策略已經失效，因為高達 **70% 的高危險 CVSS 漏洞從未在真實世界中被武器化利用**。
    
    本系統實作了業界標準的 **「三階段篩選機制」**，結合了以下三大權威情報源，幫助防守方將有限的修補資源，精準投入在最危險的漏洞上。
    """)

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        ### 🛡️ 階段 1：真實攻擊跡象 (CISA KEV)
        **CISA Known Exploited Vulnerabilities (KEV) Catalog** 
        * **定義**：由美國國土安全部轄下 CISA 維護的資料庫，收錄了「確定在真實世界（野外）已被駭客或 APT 組織利用」的漏洞。
        * **系統邏輯**：只要漏洞名列 KEV，無視 CVSS 分數，系統將強制判定為 **🔴 P0 - Emergency (24-48 小時內修補)**。
        * **參考來源**：[CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
        """)

        st.markdown(f"""
        ### 📊 階段 2：未來利用機率預測 (FIRST.org EPSS)
        **Exploit Prediction Scoring System (EPSS)**
        * **定義**：由 FIRST.org 維護的機器學習模型，每天預測每個 CVE 在未來 30 天內被利用的機率 (0% ~ 100%)。
        * **系統邏輯**：未命中 KEV 但 EPSS 機率超過設定門檻（目前設定 > {int(epss_threshold*100)}%）的漏洞，代表即將發生攻擊，判定為 **🟠 P1 - Critical (7 天內修補)**。
        * **參考來源**：[FIRST EPSS 官網](https://www.first.org/epss/)
        """)

    with col2:
        st.markdown(f"""
        ### 💣 階段 3：傳統嚴重度與資產暴露面 (NVD CVSS + 網際網路曝露)
        **National Vulnerability Database (NVD) & CVSS**
        * **定義**：NVD 提供的 Common Vulnerability Scoring System (CVSS) 反映漏洞本身的技術嚴重性。
        * **系統邏輯**：未命中前兩階段的漏洞，回歸技術評估。若 CVSS 達到門檻（目前設定 ≥ {cvss_threshold}）：
          * 若為對外公開資產 (Internet-Facing)：判定為 **🟡 P2 - High (14 天內修補)**。
          * 若為內網資產 (Internal)：判定為 **🔵 P3 - Medium (30 天內修補)**。
        * **參考來源**：[NVD CVSS 計算器](https://nvd.nist.gov/vuln-metrics/cvss)
        """)

        st.info("🟢 其他未達上述條件之漏洞，系統皆判定為 **P4 - Low (可暫緩修補)**，大幅降低資安與 IT 團隊的告警疲勞 (Alert Fatigue)。")

    st.divider()
    st.markdown("💡 **架構設計理念**：這套系統實踐了 Gartner 提出的 RBVM (Risk-Based Vulnerability Management) 方法論，透過自動化串接 API，將原本需要人工比對數小時的情報工作，縮短至幾秒鐘內完成。")

# ==================== TAB 2: 自動撈取 CISA 即時最新攻擊 ====================
with tab2:
    st.subheader("🔥 美國 CISA KEV 弱點動態威脅儀表板")
    
    if not cisa_kev_dict:
        st.warning("目前無法取得 CISA KEV 資料，請檢查網路連線後重新整理頁面。")
    else:
        data_scope = st.radio(
            "選擇監控數據範圍：",
            ["最新 100 筆 (快速)", "最新 500 筆 (預設)", f"全量監控 (全部 {len(cisa_kev_dict)} 筆)"],
            index=1, 
            horizontal=True
        )
        
        if "100" in data_scope:
            latest_kev = list(cisa_kev_dict.values())[:100]
        elif "500" in data_scope:
            latest_kev = list(cisa_kev_dict.values())[:500]
        else:
            latest_kev = list(cisa_kev_dict.values())

        kev_cves = [item['cveID'] for item in latest_kev]
        
        with st.spinner(f"正在為 {len(latest_kev)} 筆 KEV 弱點向 EPSS API 查詢最新威脅機率... (全量查詢約需 3-6 秒)"):
            epss_map_kev = fetch_epss_scores(kev_cves)

        kev_list = []
        threshold_pct = int(epss_threshold * 100)
        for k in latest_kev:
            cve = k['cveID']
            epss_val = epss_map_kev.get(cve, 0.0)
            vendor = k.get('vendorProject', 'Unknown')
            product = k.get('product', 'Unknown')
            date_added = k.get('dateAdded', 'Unknown')
            
            if epss_val >= 0.5:
                epss_level = "極高危險 (≥50%)"
            elif epss_val >= epss_threshold:
                epss_level = f"高警戒 (≥{threshold_pct}%)"
            else:
                epss_level = f"中低威脅 (<{threshold_pct}%)"

            kev_list.append({
                "CVE 編號": cve,
                "廠商": vendor,
                "產品": product,
                "廠商與產品": f"{vendor} - {product}",
                "弱點名稱": k.get('vulnerabilityName'),
                "EPSS 機率數值": epss_val,
                "EPSS 攻擊機率": f"{epss_val*100:.1f}%",
                "EPSS 風險等級": epss_level,
                "新增日期": date_added,
                "優先級": "🔴 P0 - Emergency"
            })

        df_kev = pd.DataFrame(kev_list)

        st.markdown(f"### 📊 統計結果 (範圍: {len(latest_kev)} 筆)")
        
        col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)
        total_count = len(df_kev)
        high_epss_count = len(df_kev[df_kev["EPSS 機率數值"] >= epss_threshold])
        top_vendor = df_kev["廠商"].mode()[0] if not df_kev.empty else "N/A"
        avg_epss = df_kev["EPSS 機率數值"].mean() * 100

        col_kpi1.metric("當前分析筆數", f"{total_count} 筆")
        col_kpi2.metric("高 EPSS 警戒數", f"{high_epss_count} 筆", delta=f"{high_epss_count/total_count*100:.1f}% 佔比", delta_color="inverse")
        col_kpi3.metric("受害最多廠商", top_vendor)
        col_kpi4.metric("平均 EPSS 機率", f"{avg_epss:.1f}%")

        st.divider()

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.markdown("#### 🎯 EPSS 利用機率區間分佈")
            epss_counts = df_kev["EPSS 風險等級"].value_counts()
            st.bar_chart(epss_counts, color="#FF4B4B")

        with chart_col2:
            st.markdown("#### 🏢 受害最嚴重的前 10 大廠商 (Top 10 Vendors)")
            top_10_vendors = df_kev["廠商"].value_counts().head(10)
            st.bar_chart(top_10_vendors, color="#0083B8")

        st.divider()

        st.markdown("### 📋 KEV 弱點清單明細")
        df_display = df_kev[["CVE 編號", "廠商與產品", "弱點名稱", "EPSS 攻擊機率", "EPSS 風險等級", "新增日期", "優先級"]]
        st.dataframe(df_display, use_container_width=True)

        csv_kev = df_display.to_csv(index=False).encode('utf-8-sig')
        st.download_button(
            label=f"📥 下載 {len(latest_kev)} 筆 CISA KEV 情報報告 (CSV)",
            data=csv_kev,
            file_name=f"cisa_kev_{len(latest_kev)}_report.csv",
            mime="text/csv"
        )

# ==================== TAB 3: 自訂輸入/貼上 CVE 清單 ====================
with tab3:
    st.subheader("輸入或貼上你要評估的弱點清單")
    
    cve_input_text = st.text_area(
        "請輸入 CVE 編號（每行一個，支援自動過濾雜訊）", 
        value="CVE-2023-38606\nCVE-2021-44228\nCVE-2023-23397\nCVE-2020-1350\nCVE-2018-11776\nCVE-2024-30078",
        height=150
    )
    
    col_a, col_b = st.columns(2)
    default_cvss = col_a.number_input("備用 CVSS 分數 (若 NVD 未收錄或查詢失敗時使用)", value=8.0, min_value=0.0, max_value=10.0)
    is_public = col_b.checkbox("資產權重：是否為對外網際網路資產 (Internet-Facing)", value=True)

    if st.button("🚀 開始評估輸入弱點", type="primary"):
        raw_cves = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', cve_input_text.upper())))
        
        if not raw_cves:
            st.warning("⚠️ 未檢測到有效的 CVE 編號，請確認輸入格式 (例如: CVE-2021-44228)。")
        else:
            with st.spinner(f"正在向 EPSS 與 NVD 查詢 {len(raw_cves)} 個弱點情報..."):
                epss_map = fetch_epss_scores(raw_cves)
                results = []
                for cve in raw_cves:
                    epss = epss_map.get(cve, 0.0)
                    in_kev = cve in cisa_kev_dict
                    
                    real_cvss = get_nvd_cvss(cve, nvd_api_key)
                    cvss = real_cvss if real_cvss is not None else default_cvss
                    cvss_source = "NVD 官方" if real_cvss is not None else "使用者預設"

                    if in_kev:
                        priority, sla = "P0 - Emergency", "24-48 小時內"
                        reason = "🔴 [階段 1] CISA KEV 證實已被野外武器化攻擊！"
                    elif epss >= epss_threshold:
                        priority, sla = "P1 - Critical", "7 天內"
                        reason = f"🟠 [階段 2] EPSS 機率 {epss*100:.1f}% ≥ {epss_threshold*100:.0f}%"
                    elif cvss >= cvss_threshold and is_public:
                        priority, sla = "P2 - High", "14 天內"
                        reason = f"🟡 [階段 3] 對外資產且 CVSS={cvss} ≥ {cvss_threshold}"
                    elif cvss >= cvss_threshold and not is_public:
                        priority, sla = "P3 - Medium", "30 天內"
                        reason = "🔵 [階段 3] 內網資產，無公開熱門攻擊跡象"
                    else:
                        priority, sla = "P4 - Low", "可暫緩"
                        reason = "🟢 [階段 3] 低危害弱點"

                    results.append({
                        "CVE 編號": cve,
                        "優先級": priority,
                        "建議 SLA": sla,
                        "EPSS 機率": f"{epss*100:.2f}%",
                        "CVSS 分數": f"{cvss} ({cvss_source})",
                        "CISA KEV": "⚠️ 是" if in_kev else "否",
                        "判定原因": reason
                    })

            df_results = pd.DataFrame(results)
            st.dataframe(df_results, use_container_width=True)

            csv_data = df_results.to_csv(index=False).encode('utf-8-sig')
            st.download_button(
                label="📥 下載評估報告 (CSV)",
                data=csv_data,
                file_name="vulnerability_assessment_report.csv",
                mime="text/csv"
            )