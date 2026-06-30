import streamlit as st
import feedparser
from bs4 import BeautifulSoup
import json
from datetime import datetime
import re
from langchain_groq import ChatGroq
from streamlit_autorefresh import st_autorefresh
import streamlit.components.v1 as components

# --- 1. CONFIGURAZIONE PAGINA (DEVE ESSERE IL PRIMO COMANDO) ---
st.set_page_config(page_title="SOC Threat Intel Dashboard", layout="wide", initial_sidebar_state="expanded")

# --- 2. CSS PER RIMUOVERE IL MARGINE SUPERIORE E JS PER SCROLL ---
st.markdown(
    """
    <style>
        .block-container {
            padding-top: 1rem !important;
            padding-bottom: 0rem !important;
        }
    </style>
    """,
    unsafe_allow_html=True
)

st_autorefresh(interval=300000, limit=None, key="feed_autorefresh")

GROQ_API_KEY = st.secrets["GROQ_API_KEY"]

# --- FUNZIONI DI SUPPORTO ---
def clean_html(raw_html):
    if not raw_html: return ""
    return BeautifulSoup(raw_html, "html.parser").get_text(separator=" ", strip=True)

def extract_json_from_response(text):
    # Metodo più robusto: prende dal primo '{' all'ultimo '}'
    start = text.find('{')
    end = text.rfind('}')
    if start != -1 and end != -1:
        return text[start:end+1]
    return text

def scroll_to_bottom():
    """Forza il browser a scorrere fluidamente verso il basso con un ritardo tattico"""
    js = """
    <script>
        setTimeout(() => {
            const doc = window.parent.document;
            // Intercetta il container principale di Streamlit
            const main_container = doc.querySelector('.main') || doc.querySelector('.block-container');
            if (main_container) {
                main_container.scrollTo({ top: main_container.scrollHeight, behavior: 'smooth' });
            }
        }, 500); // 500 millisecondi di ritardo per far respirare il DOM
    </script>
    """
    components.html(js, height=0)

@st.cache_data(ttl=300)
def fetch_rss_feeds():
    feeds = {
        "🇮🇹 CSIRT Italia": "https://www.csirt.gov.it/feed/avvisi",
        "🇮🇹 RedHotCyber": "https://www.redhotcyber.com/feed/",
        "🇮🇹 DDay.it - Sicurezza": "https://www.dday.it/feed/categoria/sicurezza",
        "🌐 CISA Alerts": "https://www.cisa.gov/cybersecurity-alerts-and-advisories/all.xml",
        "🌐 BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "🌐 The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
        "🌐 Krebs on Security": "https://krebsonsecurity.com/feed/",
        "🌐 Dark Reading": "https://www.darkreading.com/rss.xml",
        "🔴 Malwarebytes Labs": "https://www.malwarebytes.com/feed/",
        "🔴 Cisco Talos": "https://blog.talosintelligence.com/feeds/all.xml.rss",
        "🔴 Sophos Labs": "https://www.sophos.com/en-us/press-office/press-releases.aspx",
        "🔴 Kaspersky Lab": "https://www.kaspersky.com/blog/feed/",
        "💀 Ransomware Advisories": "https://www.cisa.gov/sites/default/files/xml/ransomware_advisory.xml",
        "💀 No More Ransom": "https://www.nomoreransom.org/feed/en.xml",
        "☁️ AWS Security": "https://aws.amazon.com/security/security-updates/",
        "☁️ Microsoft Security": "https://msrc.microsoft.com/feed",
        "☁️ Google Security": "https://security.googleblog.com/feeds/posts/default",
        "🏭 ICS-CERT Alerts": "https://www.cisa.gov/cybersecurity-alerts-and-advisories/industrial-control-systems.xml",
        "🏭 SCADA Security": "https://www.digitalbond.com/feed/",
        "🔗 NVD (NIST)": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json",
        "🔗 Exploit-DB": "https://www.exploit-db.com/rss.xml",
        "📊 Mandiant Blog": "https://www.mandiant.com/resources/blog",
        "📊 CrowdStrike Falcon": "https://www.crowdstrike.com/blog/feed/",
        "📊 Trend Micro": "https://www.trendmicro.com/en_us/research.html",
        "📱 Zimperium Labs": "https://blog.zimperium.com/feed/",
        "📱 Cellebrite": "https://www.cellebrite.com/en/blog/",
        "⚖️ GDPR.eu": "https://gdpr.eu/rss/",
        "⚖️ Privacy Affairs": "https://www.privacyaffairs.com/feed/",
    }
    
    articles = []
    for source_name, url in feeds.items():
        try:
            parsed = feedparser.parse(url)
            for entry in parsed.entries[:2]:
                raw_text = entry.get('summary', entry.get('description', entry.get('content', [{}])[0].get('value', '')))
                if not raw_text: continue
                articles.append({
                    "title": entry.get('title', 'Nessun Titolo'),
                    "link": entry.get('link', ''),
                    "content": clean_html(raw_text),
                    "source": source_name
                })
        except Exception:
            pass 
    return articles

def get_fallback_analysis(errore=""):
    return {
        "riassunto": f"L'analisi automatica non è andata a buon fine. Dettaglio: {errore}",
        "vettore_attacco": "Dato non disponibile", 
        "tecnica_exploit": "Dato non disponibile", 
        "timeline_attacco": [], 
        "indicatori_compromissione": [], 
        "impatto_tecnico": "Dato non disponibile", 
        "mitre_attack_ttp": [], 
        "raccomandazioni_difesa": [], 
        "domande_esplorative": [], 
        "anatomia_attacco": "Simulazione non disponibile."
    }

def analyze_article(title, content):
    llm = ChatGroq(
        temperature=0.1, 
        model_name="llama-3.1-8b-instant", 
        groq_api_key=GROQ_API_KEY,
        max_tokens=4000, 
        model_kwargs={"response_format": {"type": "json_object"}}
    )
    
    # Prompt corretto: regole rigide per impedire al LLM di invalidare il JSON
    prompt = f"""
    Analizza questo bollettino cyber e restituisci ESCLUSIVAMENTE un oggetto JSON valido in italiano.
    
    REGOLE FONDAMENTALI PER IL JSON:
    1. Fai l'escape di tutte le virgolette doppie (\\") all'interno dei testi.
    2. Usa '\\n' per i ritorni a capo, non andare mai a capo fisicamente all'interno di una stringa JSON.
    3. Non aggiungere alcun testo introduttivo o conclusivo fuori dalle parentesi graffe {{ }}.
    
    Struttura JSON obbligatoria (chiavi in minuscolo):
    {{
        "riassunto": "Sintesi executive...",
        "vettore_attacco": "Testo descrittivo...",
        "tecnica_exploit": "Testo descrittivo...",
        "impatto_tecnico": "Testo descrittivo...",
        "anatomia_attacco": "Testo con spiegazione...",
        "mitre_attack_ttp": ["TTP1", "TTP2"],
        "indicatori_compromissione": ["IoC1", "IoC2"],
        "raccomandazioni_difesa": ["Azione 1", "Azione 2"],
        "domande_esplorative": ["Domanda 1", "Domanda 2"],
        "timeline_attacco": [
            {{"fase": "Nome fase 1", "descrizione": "Cosa succede qui"}},
            {{"fase": "Nome fase 2", "descrizione": "Cosa succede qui"}}
        ]
    }}
    
    Articolo: {title}
    Testo: {content[:1500]}
    """
    
    try:
        response = llm.invoke(prompt)
        json_text = extract_json_from_response(response.content)
        raw_json = json.loads(json_text)
        
        clean_json = {str(k).lower(): v for k, v in raw_json.items()}
        
        required_lists = ["mitre_attack_ttp", "indicatori_compromissione", "raccomandazioni_difesa", "domande_esplorative", "timeline_attacco"]
        for k in required_lists:
            if k not in clean_json or not isinstance(clean_json[k], list):
                clean_json[k] = []
                
        required_strings = ["riassunto", "vettore_attacco", "tecnica_exploit", "impatto_tecnico", "anatomia_attacco"]
        for k in required_strings:
            if k not in clean_json or not isinstance(clean_json[k], str) or not clean_json[k]:
                clean_json[k] = "Dato non disponibile."

        return clean_json
        
    except json.JSONDecodeError as e:
        return get_fallback_analysis(f"Errore di formattazione dati dall'AI (JSON Decode Error).")
    except Exception as e:
        return get_fallback_analysis(f"Errore generico: {str(e)}")

def stream_deep_dive(context, question):
    llm = ChatGroq(temperature=0.3, model_name="llama-3.1-8b-instant", groq_api_key=GROQ_API_KEY)
    prompt = f"Sei un Security Engineer. Rispondi in italiano in modo tecnico. Contesto: {context}. Domanda: {question}"
    for chunk in llm.stream(prompt):
        yield chunk.content

# --- INTERFACCIA UTENTE ---
st.markdown("<h1 style='text-align: center; margin-top: 0px;'>🛡️ SOC Threat Intelligence Explorer</h1>", unsafe_allow_html=True)

with st.spinner("Sincronizzazione Feed RSS in corso..."):
    articles = fetch_rss_feeds()

if not articles:
    st.error("Nessun articolo trovato nei feed.")
else:
    if 'selected_article' not in st.session_state:
        st.session_state.selected_article = articles[0]

    st.sidebar.header("📡 Live Feed Alerts")
    
    sidebar_widget = """
    <div style="text-align: center; font-family: sans-serif; padding: 15px; background: #1e1e1e; border-radius: 10px; margin-bottom: 20px; border: 1px solid #333;">
        <style>
            @keyframes search { 0% {transform: translateX(0);} 50% {transform: translateX(10px);} 100% {transform: translateX(0);} }
            .owl { font-size: 45px; display: block; animation: search 2s infinite ease-in-out; margin-bottom: 10px;}
            .timer-box { background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); color: white; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 24px; font-weight: bold; }
            .lbl { font-size: 11px; font-family: sans-serif; display: block; margin-bottom: 5px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;}
        </style>
        <span class="owl">🦉🔭</span>
        <div class="timer-box">
            <span class="lbl">Prossimo Refresh</span>
            <span id="time">05:00</span> 🟢
        </div>
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
    
    with st.sidebar:
        components.html(sidebar_widget, height=180)
        st.markdown('<p style="color:#888; font-size:13px; text-align:center; margin-top:-10px;">👇 Scegli un bollettino</p>', unsafe_allow_html=True)
        st.divider()
        
        for a in articles:
            if st.button(f"{a['source']}\n{a['title'][:50]}...", use_container_width=True):
                st.session_state.selected_article = a
                if 'analysis' in st.session_state: del st.session_state.analysis
                if 'deep_dive_response' in st.session_state: del st.session_state.deep_dive_response
                if 'trigger_stream' in st.session_state: del st.session_state.trigger_stream

    current_art = st.session_state.selected_article
    st.markdown(f"### 📰 {current_art['title']}")
    st.caption(f"**Fonte:** {current_art['source']} | [Link Ufficiale]({current_art['link']})")
    
    content_preview = current_art['content'][:800] + "..." if current_art['content'] else "Testo dell'articolo non estraibile."
    st.write(content_preview)

    if st.button("🚀 Avvia Analisi AI Cloud", type="primary"):
        with st.spinner("L'intelligenza Artificiale sta estraendo i dati..."):
            st.session_state.analysis = analyze_article(current_art['title'], current_art['content'])

    if st.session_state.get('analysis'):
        a = st.session_state.analysis
        
        if a.get('riassunto').startswith("L'analisi automatica non è andata"):
            st.error(a.get('riassunto'))
        
        st.markdown("---")
        col1, col2 = st.columns([1.5, 1])
        
        with col1:
            st.markdown("#### 📝 Executive Summary")
            st.info(a.get('riassunto'))
            
            st.markdown("#### 💬 Chat con l'Esperto SOC")
            with st.form(key="custom_chat_form", clear_on_submit=True):
                custom_q = st.text_input("Approfondisci tecnicamente questo alert:", max_chars=200)
                if st.form_submit_button("Invia Domanda") and custom_q:
                    st.session_state.active_question = custom_q
                    st.session_state.trigger_stream = True
                    st.rerun() # <-- Ricarica Immediata

            st.markdown("<br>", unsafe_allow_html=True)
            
            with st.expander("🔬 ANATOMIA DELL'ATTACCO E SIMULAZIONE", expanded=True):
                st.markdown(a.get('anatomia_attacco'))
                
            with st.expander("⏱️ TIMELINE DELL'ATTACCO", expanded=True):
                timeline_data = a.get('timeline_attacco', [])
                if isinstance(timeline_data, list) and len(timeline_data) > 0:
                    html_timeline = '<div style="border-left: 3px solid #ff4b4b; padding-left: 20px; margin-left: 10px;">\n'
                    for step in timeline_data:
                        fase = step.get('fase', 'Fase')
                        desc = step.get('descrizione', '')
                        html_timeline += f'<div style="position: relative; margin-bottom: 20px;">\n'
                        html_timeline += f'<span style="position: absolute; left: -31px; top: 2px; background-color: #ff4b4b; width: 18px; height: 18px; border-radius: 50%; border: 3px solid #1e1e1e;"></span>\n'
                        html_timeline += f'<h5 style="margin:0; color: #ff4b4b;">{fase}</h5>\n'
                        html_timeline += f'<p style="margin: 5px 0 0 0; font-size: 14px;">{desc}</p>\n'
                        html_timeline += f'</div>\n'
                    html_timeline += '</div>'
                    st.markdown(html_timeline, unsafe_allow_html=True)
                else:
                    st.write("Dati strutturati per la timeline non disponibili per questo attacco.")
                    
        with col2:
            st.markdown("#### 🔍 Investigazione")
            domande = a.get('domande_esplorative', [])
            if domande:
                for idx, domanda in enumerate(domande):
                    # Uso di un key univoco per il bottone
                    if st.button(f"🔎 {domanda}", key=f"btn_dom_{idx}"):
                        st.session_state.active_question = domanda
                        st.session_state.trigger_stream = True
                        st.rerun() # <-- Ricarica Immediata
            else:
                st.write("Nessuna domanda disponibile.")
            
            st.markdown("#### 🎯 MITRE ATT&CK TTPs")
            ttps = a.get('mitre_attack_ttp', [])
            if ttps:
                for ttp in ttps: st.code(str(ttp), language="text")
            else:
                st.write("Nessuna TTP identificata.")
            
            st.markdown("#### 🔗 Indicatori (IoC)")
            with st.container(border=True):
                iocs = a.get('indicatori_compromissione', [])
                if iocs:
                    for ioc in iocs: st.code(str(ioc), language="text")
                else:
                    st.write("Nessun IoC rilevato nel testo.")
                
                st.divider()
                st.markdown("#### 1️⃣ Vettore Iniziale")
                st.write(a.get('vettore_attacco'))
                
                st.markdown("#### 💣 Tecnica Exploit")
                st.write(a.get('tecnica_exploit'))
                
                st.markdown("#### 💥 Impatto sui Sistemi")
                st.write(a.get('impatto_tecnico'))

            st.markdown("#### 🛡️ Raccomandazioni")
            with st.container(border=True):
                recs = a.get('raccomandazioni_difesa', [])
                if recs:
                    for i, rec in enumerate(recs, 1): st.markdown(f"**{i}.** {rec}")
                else:
                    st.write("Nessuna raccomandazione specifica.")

    # --- SEZIONE RISPOSTA E TRIGGER SCROLL ---
    if st.session_state.get('trigger_stream', False):
        st.markdown("---")
        st.markdown(f"### 💡 Risposta in tempo reale: *{st.session_state.active_question}*")
        ctx = f"Articolo: {current_art['title']}. Riassunto: {a.get('riassunto')}"
        
        # Esegue lo scroll PRIMA di iniziare a scrivere il testo, così l'utente vede il caricamento
        scroll_to_bottom() 
        
        with st.chat_message("assistant", avatar="🤖"):
            full_resp = st.write_stream(stream_deep_dive(ctx, st.session_state.active_question))
            
        st.session_state.deep_dive_response = full_resp
        st.session_state.trigger_stream = False
        
    elif 'deep_dive_response' in st.session_state and st.session_state.get('active_question'):
        st.markdown("---")
        st.markdown(f"### 💡 Risposta: *{st.session_state.active_question}*")
        with st.chat_message("assistant", avatar="🤖"):
            st.write(st.session_state.deep_dive_response)
        
        # Esegue lo scroll alla fine se la risposta è già pronta a schermo
        scroll_to_bottom()
