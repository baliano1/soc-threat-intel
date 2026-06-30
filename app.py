import streamlit as st
import feedparser
from bs4 import BeautifulSoup
import json
from datetime import datetime
import re
from langchain_groq import ChatGroq
from streamlit_autorefresh import st_autorefresh
import streamlit.components.v1 as components

# --- CONFIGURAZIONE ---
st.set_page_config(page_title="SOC Threat Intel Dashboard", layout="wide", initial_sidebar_state="expanded")

# Ricarica la pagina silenziosamente ogni 5 minuti (300.000 ms)
st_autorefresh(interval=300000, limit=None, key="feed_autorefresh")

GROQ_API_KEY = st.secrets["GROQ_API_KEY"]

# --- FUNZIONI DI SUPPORTO ---
def clean_html(raw_html):
    if not raw_html: return ""
    return BeautifulSoup(raw_html, "html.parser").get_text(separator=" ", strip=True)

def extract_json_from_response(text):
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        return match.group(0)
    return text

@st.cache_data(ttl=300)
def fetch_rss_feeds():
    feeds = {
        # --- FONTI ITALIANE ---
        "🇮🇹 CSIRT Italia": "https://www.csirt.gov.it/feed/avvisi",
        "🇮🇹 RedHotCyber": "https://www.redhotcyber.com/feed/",
        "🇮🇹 DDay.it - Sicurezza": "https://www.dday.it/feed/categoria/sicurezza",
        
        # --- FONTI GLOBALI - ADVISORY E VULNERABILITÀ ---
        "🌐 CISA Alerts": "https://www.cisa.gov/cybersecurity-alerts-and-advisories/all.xml",
        "🌐 BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "🌐 The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
        "🌐 Krebs on Security": "https://krebsonsecurity.com/feed/",
        "🌐 Dark Reading": "https://www.darkreading.com/rss.xml",
        
        # --- FONTI SPECIALIZZATE - MALWARE E THREAT INTEL ---
        "🔴 Malwarebytes Labs": "https://www.malwarebytes.com/feed/",
        "🔴 Cisco Talos": "https://blog.talosintelligence.com/feeds/all.xml.rss",
        "🔴 Sophos Labs": "https://www.sophos.com/en-us/press-office/press-releases.aspx",
        "🔴 Kaspersky Lab": "https://www.kaspersky.com/blog/feed/",
        
        # --- FONTI SPECIALIZZATE - RANSOMWARE ---
        "💀 Ransomware Advisories": "https://www.cisa.gov/sites/default/files/xml/ransomware_advisory.xml",
        "💀 No More Ransom": "https://www.nomoreransom.org/feed/en.xml",
        
        # --- FONTI SPECIALIZZATE - CLOUD & INFRASTRUCTURE ---
        "☁️ AWS Security": "https://aws.amazon.com/security/security-updates/",
        "☁️ Microsoft Security": "https://msrc.microsoft.com/feed",
        "☁️ Google Security": "https://security.googleblog.com/feeds/posts/default",
        
        # --- FONTI SPECIALIZZATE - IoT E OT ---
        "🏭 ICS-CERT Alerts": "https://www.cisa.gov/cybersecurity-alerts-and-advisories/industrial-control-systems.xml",
        "🏭 SCADA Security": "https://www.digitalbond.com/feed/",
        
        # --- FONTI SPECIALIZZATE - API & APPLICAZIONI ---
        "🔗 NVD (NIST)": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json",
        "🔗 Exploit-DB": "https://www.exploit-db.com/rss.xml",
        
        # --- FONTI SPECIALIZZATE - REPORT E ANALISI ---
        "📊 Mandiant Blog": "https://www.mandiant.com/resources/blog",
        "📊 CrowdStrike Falcon": "https://www.crowdstrike.com/blog/feed/",
        "📊 Trend Micro": "https://www.trendmicro.com/en_us/research.html",
        
        # --- FONTI SPECIALIZZATE - SICUREZZA MOBILE ---
        "📱 Zimperium Labs": "https://blog.zimperium.com/feed/",
        "📱 Cellebrite": "https://www.cellebrite.com/en/blog/",
        
        # --- FONTI SPECIALIZZATE - PRIVACY E COMPLIANCE ---
        "⚖️ GDPR.eu": "https://gdpr.eu/rss/",
        "⚖️ Privacy Affairs": "https://www.privacyaffairs.com/feed/",
    }
    
    articles = []
    for source_name, url in feeds.items():
        try:
            parsed = feedparser.parse(url)
            for entry in parsed.entries[:2]:
                raw_text = entry.get('summary', entry.get('description', entry.get('content', [{}])[0].get('value', '')))
                articles.append({
                    "title": entry.get('title', 'Nessun Titolo'),
                    "link": entry.get('link', ''),
                    "content": clean_html(raw_text),
                    "source": source_name
                })
        except Exception:
            pass 
    return articles

def analyze_article(title, content):
    llm = ChatGroq(
        temperature=0.1, 
        model_name="llama-3.1-8b-instant", 
        groq_api_key=GROQ_API_KEY,
        max_tokens=4000, 
        model_kwargs={"response_format": {"type": "json_object"}}
    )
    
    prompt = f"""
    Analizza questo articolo di cybersecurity e rispondi ESCLUSIVAMENTE con un oggetto JSON valido in lingua italiana.
    Non inserire testo fuori dal JSON.

    Chiavi obbligatorie (tutte in minuscolo): 
    "riassunto", "vettore_attacco", "tecnica_exploit", "timeline_attacco", "indicatori_compromissione", "impatto_tecnico", "mitre_attack_ttp", "raccomandazioni_difesa", "domande_esplorative", "anatomia_attacco".
    
    Istruzioni di Stile:
    - "timeline_attacco": Formattala come una lista puntata rigorosa in Markdown.
    - "anatomia_attacco": Crea una spiegazione altamente tecnica e professionale. Usa blocchi di codice Markdown (es. ```bash) per mostrare payload di esempio, script malevoli o simulazioni realistiche.
    
    Articolo: {title}
    Testo: {content[:1500]}
    """
    
    try:
        response = llm.invoke(prompt)
        json_text = extract_json_from_response(response.content)
        raw_json = json.loads(json_text)
        
        clean_json = {str(k).lower(): v for k, v in raw_json.items()}
        required_keys = ["riassunto", "vettore_attacco", "tecnica_exploit", "timeline_attacco", "indicatori_compromissione", "impatto_tecnico", "mitre_attack_ttp", "raccomandazioni_difesa", "domande_esplorative", "anatomia_attacco"]
        
        for key in required_keys:
            if key not in clean_json:
                clean_json[key] = [] if key in ["indicatori_compromissione", "mitre_attack_ttp", "raccomandazioni_difesa", "domande_esplorative"] else "Dato non disponibile"
        return clean_json
        
    except Exception as e:
        st.error("❌ Errore durante l'analisi. Riprova.")
        return None

def stream_deep_dive(context, question):
    llm = ChatGroq(temperature=0.3, model_name="llama-3.1-8b-instant", groq_api_key=GROQ_API_KEY)
    prompt = f"Sei un Senior Security Engineer. RISPONDI IN ITALIANO, in modo tecnico. Contesto: {context}. Domanda: {question}"
    for chunk in llm.stream(prompt):
        yield chunk.content

# --- INTERFACCIA UTENTE ---
st.title("🛡️ SOC Threat Intelligence Explorer")

with st.spinner("Sincronizzazione Feed RSS in corso..."):
    articles = fetch_rss_feeds()

if not articles:
    st.error("Impossibile recuperare gli articoli.")
else:
    if 'selected_article' not in st.session_state:
        st.session_state.selected_article = articles[0]

    st.sidebar.header("📡 Live Feed Alerts")
    
    # --- ANIMAZIONE GUFETTO IN HTML/CSS NATIVO ---
    gufetto_html = """
    <style>
    .owl-container { text-align: center; font-size: 40px; margin: 10px 0; animation: search 2s infinite ease-in-out; }
    @keyframes search { 0% {transform: translateX(0);} 50% {transform: translateX(15px);} 100% {transform: translateX(0);} }
    </style>
    <div class="owl-container">🦉🔭</div>
    """
    st.sidebar.markdown(gufetto_html, unsafe_allow_html=True)
    
    # --- TIMER JAVASCRIPT INDIPENDENTE (Non blocca Streamlit) ---
    timer_html = """
    <style>
    .timer-box { background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); color: white; padding: 10px; border-radius: 8px; text-align: center; font-family: monospace; font-size: 24px; font-weight: bold; }
    .label { font-size: 12px; font-family: sans-serif; display: block; margin-bottom: 5px; opacity: 0.9;}
    </style>
    <div class="timer-box">
        <span class="label">Prossimo refresh</span>
        <span id="time">05:00</span> 🟢
    </div>
    <script>
    var timeLeft = 300;
    setInterval(function(){
        timeLeft--;
        if(timeLeft <= 0) timeLeft = 300;
        var m = Math.floor(timeLeft / 60);
        var s = timeLeft % 60;
        document.getElementById('time').innerText = (m < 10 ? "0"+m : m) + ":" + (s < 10 ? "0"+s : s);
    }, 1000);
    </script>
    """
    components.html(timer_html, height=90)
    
    st.sidebar.markdown('<p style="color:#888; font-size:13px; text-align:center;">Scegli un bollettino 👇</p>', unsafe_allow_html=True)
    
    for a in articles:
        if st.sidebar.button(f"{a['source']}\n{a['title'][:50]}...", use_container_width=True):
            st.session_state.selected_article = a
            if 'analysis' in st.session_state: del st.session_state.analysis
            if 'deep_dive_response' in st.session_state: del st.session_state.deep_dive_response
            if 'trigger_stream' in st.session_state: del st.session_state.trigger_stream

    current_art = st.session_state.selected_article
    st.markdown(f"### 📰 {current_art['title']}")
    st.caption(f"**Fonte:** {current_art['source']} | [Link Ufficiale]({current_art['link']})")
    st.write(current_art['content'][:800] + "...")

    if st.button("🚀 Avvia Analisi AI Cloud", type="primary"):
        with st.spinner("Estrazione dati in corso (potrebbe richiedere 15 secondi)..."):
            st.session_state.analysis = analyze_article(current_art['title'], current_art['content'])

    if st.session_state.get('analysis'):
        a = st.session_state.analysis
        st.markdown("---")
        
        col1, col2 = st.columns([1.5, 1])
        
        with col1:
            st.markdown("#### 📝 Executive Summary")
            st.info(a.get('riassunto', 'Nessun riassunto.'))
            
            st.markdown("#### 💬 Chat con l'Esperto SOC")
            with st.form(key="custom_chat_form"):
                custom_q = st.text_input("Approfondisci tecnicamente questo alert:", max_chars=200)
                if st.form_submit_button("Invia Domanda") and custom_q:
                    st.session_state.active_question = custom_q
                    st.session_state.trigger_stream = True

            st.markdown("<br>", unsafe_allow_html=True)
            # --- SEZIONE ANATOMIA (Professionale e nativa) ---
            with st.expander("🔬 ANATOMIA DELL'ATTACCO & SCENARIO DI SIMULAZIONE", expanded=True):
                st.markdown(a.get('anatomia_attacco', 'Simulazione non disponibile.'))
                
            # --- SEZIONE TIMELINE (Professionale e nativa) ---
            with st.expander("⏱️ TIMELINE DELL'ATTACCO", expanded=True):
                st.markdown(a.get('timeline_attacco', 'Timeline non disponibile.'))
                    
        with col2:
            st.markdown("#### 🔍 Domande Esplorative")
            for domanda in a.get('domande_esplorative', []):
                if st.button(f"🔎 {domanda}", key=domanda):
                    st.session_state.active_question = domanda
                    st.session_state.trigger_stream = True
            
            st.markdown("#### 🎯 MITRE ATT&CK TTPs")
            ttps = a.get('mitre_attack_ttp', [])
            if ttps:
                for ttp in ttps: st.code(str(ttp), language="text")
            else:
                st.write("Nessuna TTP identificata.")
            
            st.markdown("#### 🔗 Indicatori di Compromissione (IoC)")
            with st.container(border=True):
                iocs = a.get('indicatori_compromissione', [])
                if iocs:
                    for ioc in iocs: st.code(str(ioc), language="text")
                else:
                    st.write("Nessun IoC rilevato nel testo.")
                
                st.divider()
                st.markdown("**Vettore Iniziale:**")
                st.write(a.get('vettore_attacco', 'N/A'))
                
                st.markdown("**Tecnica Exploit:**")
                st.write(a.get('tecnica_exploit', 'N/A'))
                
                st.markdown("**Impatto sui Sistemi:**")
                st.write(a.get('impatto_tecnico', 'N/A'))

            st.markdown("#### 🛡️ Raccomandazioni di Difesa")
            with st.container(border=True):
                recs = a.get('raccomandazioni_difesa', [])
                if recs:
                    for i, rec in enumerate(recs, 1): st.markdown(f"**{i}.** {rec}")
                else:
                    st.write("Nessuna raccomandazione specifica.")

    if st.session_state.get('trigger_stream', False):
        st.markdown("---")
        st.markdown(f"### 💡 Risposta in tempo reale: *{st.session_state.active_question}*")
        ctx = f"Articolo: {current_art['title']}. Riassunto: {a.get('riassunto')}"
        with st.chat_message("assistant", avatar="🤖"):
            full_resp = st.write_stream(stream_deep_dive(ctx, st.session_state.active_question))
        st.session_state.deep_dive_response = full_resp
        st.session_state.trigger_stream = False
        
    elif 'deep_dive_response' in st.session_state and st.session_state.get('active_question'):
        st.markdown("---")
        st.markdown(f"### 💡 Risposta: *{st.session_state.active_question}*")
        with st.chat_message("assistant", avatar="🤖"):
            st.write(st.session_state.deep_dive_response)
