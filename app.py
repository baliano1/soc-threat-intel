import streamlit as st
import feedparser
from bs4 import BeautifulSoup
import json
import time
from datetime import datetime
from langchain_groq import ChatGroq
from streamlit_autorefresh import st_autorefresh

# --- CONFIGURAZIONE ---
st.set_page_config(page_title="SOC Threat Intel Dashboard", layout="wide", initial_sidebar_state="expanded")
st_autorefresh(interval=1000, limit=None, key="feed_autorefresh")

# Recupero della chiave API dai segreti di Streamlit
GROQ_API_KEY = st.secrets["GROQ_API_KEY"]

# --- CSS PERSONALIZZATO PER ANIMAZIONE GUFETTO ---
st.markdown("""
<style>
@keyframes owl_search {
    0% { transform: translateX(0px); }
    50% { transform: translateX(15px); }
    100% { transform: translateX(0px); }
}

@keyframes binoculars_rotate {
    0%, 100% { transform: rotate(0deg); }
    25% { transform: rotate(-5deg); }
    75% { transform: rotate(5deg); }
}

.owl_container {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    margin: 15px 0;
    animation: owl_search 2s infinite ease-in-out;
}

.owl_face {
    font-size: 48px;
    font-weight: bold;
}

.binoculars {
    font-size: 36px;
    animation: binoculars_rotate 2s infinite ease-in-out;
    transform-origin: center;
}

.countdown_box {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 12px;
    border-radius: 8px;
    text-align: center;
    margin: 10px 0;
    font-weight: bold;
    font-size: 16px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.countdown_label {
    font-size: 12px;
    opacity: 0.9;
    margin-bottom: 5px;
}

.countdown_time {
    font-size: 24px;
    font-family: 'Courier New', monospace;
}

.pulse_indicator {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: #10b981;
    margin-left: 8px;
    animation: pulse 1.5s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
}

.helper_text {
    font-size: 14px;
    font-weight: 500;
    color: #666;
    margin: 10px 0;
    padding: 5px 0;
}
</style>
""", unsafe_allow_html=True)

def clean_html(raw_html):
    if not raw_html: return ""
    return BeautifulSoup(raw_html, "html.parser").get_text(separator=" ", strip=True)

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
        "🌐 Darkside Hackers": "https://www.darkreading.com/threat-intelligence/feed",
        
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
            for entry in parsed.entries[:2]:  # Ridotto a 2 per non sovraccaricare
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
    # Inizializziamo Groq in modalità JSON per forzare l'output corretto
    llm = ChatGroq(
        temperature=0, 
        model_name="llama-3.1-8b-instant", 
        groq_api_key=GROQ_API_KEY,
        model_kwargs={"response_format": {"type": "json_object"}}
    )
    
    prompt = f"""
    Genera ESCLUSIVAMENTE un oggetto JSON valido. RISPONDI RIGOROSAMENTE IN ITALIANO.
    Usa ESATTAMENTE queste tre chiavi, rigorosamente in minuscolo: "riassunto", "mitre_attack_ttp", "domande_esplorative".
    
    Struttura JSON richiesta:
    {{
        "riassunto": "Riassunto analitico di 4 frasi in italiano (Chi è attaccato, vettore d'attacco, impatto).",
        "mitre_attack_ttp": ["Lista codici TTP o tecniche citate"],
        "domande_esplorative": [
            "Come funziona tecnicamente l'attacco citato?",
            "Quali sono i metodi di mitigazione in rete?",
            "Quali IoC cercare nei log?"
        ]
    }}
    
    Titolo: {title}
    Testo: {content[:1500]} 
    """
    
    # In LangChain i ChatModels restituiscono un oggetto con .content
    response = llm.invoke(prompt)
    
    try:
        raw_json = json.loads(response.content)
        clean_json = {str(k).lower(): v for k, v in raw_json.items()}
        
        for key in ["risposta", "response", "analisi", "json", "output"]:
            if key in clean_json and isinstance(clean_json[key], dict):
                clean_json = {str(k).lower(): v for k, v in clean_json[key].items()}
                break
                
        return clean_json
        
    except Exception as e:
        return {
            "riassunto": "Errore di conversione JSON. Riprova l'analisi.",
            "mitre_attack_ttp": [],
            "domande_esplorative": []
        }

def stream_deep_dive(context, question):
    llm = ChatGroq(temperature=0.3, model_name="llama-3.1-8b-instant", groq_api_key=GROQ_API_KEY)
    prompt = f"""
    Sei un Senior Security Engineer. RISPONDI RIGOROSAMENTE IN ITALIANO, in modo tecnico e professionale. 
    Contesto: {context}
    Domanda dell'utente: {question}
    """
    # Adattiamo lo streaming per Streamlit e ChatGroq
    for chunk in llm.stream(prompt):
        yield chunk.content

def format_countdown(seconds):
    """Formatta i secondi in MM:SS"""
    minutes = seconds // 60
    secs = seconds % 60
    return f"{minutes:02d}:{secs:02d}"

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
    
    # --- ANIMAZIONE GUFETTO E CONTATORE ---
    col1, col2 = st.sidebar.columns([1, 1])
    with col1:
        st.markdown("""
        <div class="owl_container">
            <span class="owl_face">🦉</span>
            <span class="binoculars">🔭</span>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        # Placeholder per il contatore - verrà aggiornato
        countdown_placeholder = st.sidebar.empty()
    
    # Inizializzazione del timer con timestamp
    if 'refresh_start_time' not in st.session_state:
        st.session_state.refresh_start_time = datetime.now()
    
    # Calcolo del tempo rimanente (aggiornamento ogni 5 minuti = 300 secondi)
    elapsed = (datetime.now() - st.session_state.refresh_start_time).total_seconds()
    remaining = max(0, 300 - int(elapsed))
    
    # Se il tempo è scaduto, ripristina il timer
    if remaining == 0:
        st.session_state.refresh_start_time = datetime.now()
        remaining = 300
    
    # Aggiornamento del contatore
    with countdown_placeholder.container():
        st.markdown(f"""
        <div class="countdown_box">
            <div class="countdown_label">Prossimo refresh</div>
            <div class="countdown_time">{format_countdown(remaining)}<span class="pulse_indicator"></span></div>
        </div>
        """, unsafe_allow_html=True)
    
    st.sidebar.caption("Si aggiorna automaticamente ogni 5 minuti.")
    
    # --- ETICHETTA HELPER PER UTENTI MOBILE ---
    st.sidebar.markdown('<div class="helper_text">👇 Scegli un bollettino da consultare</div>', unsafe_allow_html=True)
    
    st.sidebar.divider()
    
    for a in articles:
        btn_label = f"{a['source']}\n{a['title'][:50]}..."
        if st.sidebar.button(btn_label, use_container_width=True):
            st.session_state.selected_article = a
            if 'analysis' in st.session_state: del st.session_state.analysis
            if 'deep_dive_response' in st.session_state: del st.session_state.deep_dive_response
            if 'trigger_stream' in st.session_state: del st.session_state.trigger_stream

    current_art = st.session_state.selected_article
    st.markdown(f"### 📰 {current_art['title']}")
    st.caption(f"**Fonte:** {current_art['source']} | [Link Ufficiale]({current_art['link']})")
    st.write(current_art['content'][:800] + "...")

    if st.button("🚀 Avvia Analisi AI Cloud", type="primary"):
        with st.spinner("Estrazione TTP in corso sui server Groq..."):
            try:
                st.session_state.analysis = analyze_article(current_art['title'], current_art['content'])
            except Exception as e:
                st.error(f"Errore: {e}")

    if 'analysis' in st.session_state:
        analysis = st.session_state.analysis
        st.markdown("---")
        
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown("#### 📝 Riassunto")
            st.info(analysis.get('riassunto', 'Nessun riassunto generato.'))
            
            st.markdown("#### 🔍 Investigazione Tecnica")
            for domanda in analysis.get('domande_esplorative', []):
                if st.button(f"🔎 {domanda}", key=domanda):
                    st.session_state.active_question = domanda
                    st.session_state.trigger_stream = True
                    
            st.markdown("#### 💬 Chat con l'esperto")
            with st.form(key="custom_chat_form"):
                custom_q = st.text_input("Fai una domanda specifica su questo alert (max 200 caratteri):", max_chars=200)
                submit_chat = st.form_submit_button("Invia Domanda")
                if submit_chat and custom_q:
                    st.session_state.active_question = custom_q
                    st.session_state.trigger_stream = True
                    
        with col2:
            st.markdown("#### 🎯 Tag e TTP Rilevati")
            ttps = analysis.get('mitre_attack_ttp', [])
            if isinstance(ttps, list) and ttps:
                for ttp in ttps:
                    if str(ttp).strip(): st.code(str(ttp), language="text")
            else:
                st.write("Nessun pattern tecnico.")

    if st.session_state.get('trigger_stream', False):
        st.markdown("---")
        st.markdown(f"### 💡 Analisi in tempo reale: *{st.session_state.active_question}*")
        
        context_text = f"Articolo: {current_art['title']}. Riassunto: {analysis.get('riassunto')}"
        
        with st.chat_message("assistant", avatar="🤖"):
            full_response = st.write_stream(stream_deep_dive(context_text, st.session_state.active_question))
            
        st.session_state.deep_dive_response = full_response
        st.session_state.trigger_stream = False
        
    elif 'deep_dive_response' in st.session_state:
        st.markdown("---")
        st.markdown(f"### 💡 Risposta: *{st.session_state.active_question}*")
        with st.chat_message("assistant", avatar="🤖"):
            st.write(st.session_state.deep_dive_response)
