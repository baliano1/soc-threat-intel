# 🛡️ SOC Threat Intelligence Explorer

Dashboard completa per monitoraggio e analisi in tempo reale delle minacce cyber. Questo strumento aggrega automaticamente i feed RSS dai principali centri di ricerca sulla sicurezza internazionali e italiani, offrendo riassunti intelligenti e insight strategici alimentati da AI.

## ✨ Caratteristiche Principali

### 📡 Monitoraggio Live
- Aggiornamento automatico dei feed RSS ogni 5 minuti
- Rilevamento di nuove minacce in tempo reale
- Dashboard interattiva e reattiva

### 🤖 Analisi AI Istantanea
Generazione di riassunti esecutivi con focus su:
- **Attori della minaccia**: Identificazione di chi attacca e chi è colpito
- **Vettore di compromissione**: Come avviene l'attacco
- **Impatto sui sistemi**: Conseguenze tecniche e organizzative

### 🔍 Estrazione Intelligence (TTP)
- Identificazione automatica di tecniche e tattiche (TTP)
- Mappatura basata sul framework **MITRE ATT&CK**
- Correlazione con minacce note

### 💬 Chat Interattivo con AI
Interroga l'IA per:
- Approfondire aspetti tecnici e vulnerabilità
- Strategie di mitigazione e remediation
- Indicatori di compromissione (IoC) e detection rules

## 🌍 Fonti Monitorate

| Regione | Sorgente |
|---------|----------|
| 🇮🇹 Italia | CSIRT Italia (ACN) |
| 🇮🇹 Italia | RedHotCyber |
| 🌐 Globale | BleepingComputer |
| 🌐 Globale | The Hacker News |
| 🌐 Globale | CISA Cyber Alerts |

## 🛠️ Tecnologie Utilizzate

| Componente | Tecnologia |
|-----------|-----------|
| **Frontend** | Streamlit |
| **AI Engine** | Groq (LLaMA 3.1) |
| **Processing** | LangChain |
| **Linguaggio** | Python |

## 🚀 Guida di Avvio Rapido

### Prerequisiti
- Python 3.8+
- Chiave API Groq (ottienila su [groq.com](https://console.groq.com))

### Installazione

```bash
# 1. Clona il repository
git clone https://github.com/baliano1/soc-threat-intel.git
cd soc-threat-intel

# 2. Installa i requisiti
pip install -r requirements.txt

# 3. Configura le variabili d'ambiente
export GROQ_API_KEY="your-api-key-here"

# Su Windows (PowerShell)
$env:GROQ_API_KEY = "your-api-key-here"
```

### Esecuzione

```bash
streamlit run app.py
```

L'applicazione sarà disponibile su `http://localhost:8501`

## 📋 Requisiti

Consulta `requirements.txt` per tutte le dipendenze Python necessarie.

## 🤝 Contribuire

Le pull request sono benvenute! Per cambiamenti significativi:

1. Fork il repository
2. Crea un branch per la tua feature (`git checkout -b feature/amazing-feature`)
3. Commit i tuoi cambiamenti (`git commit -m 'Add amazing feature'`)
4. Push al branch (`git push origin feature/amazing-feature`)
5. Apri una Pull Request

## 📌 Note

Questo progetto è stato sviluppato per migliorare continuamente la **Situational Awareness** nel contesto della Cyber Security, con particolare attenzione al panorama minacce italiano e globale.

## 📄 Licenza

Questo progetto è rilasciato sotto licenza MIT. Consulta il file `LICENSE` per i dettagli.

## 📞 Contatti & Supporto

Per domande, segnalazioni di bug o suggerimenti, apri una [issue](https://github.com/baliano1/soc-threat-intel/issues) nel repository.

---

**Mantieni il tuo SOC sempre aggiornato sulle minacce emergenti! 🔐**
