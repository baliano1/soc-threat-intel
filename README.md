#🛡️ SOC Threat Intelligence Explorer
La dashboard definitiva per analizzare le minacce cyber in tempo reale. Questo strumento aggrega automaticamente i feed RSS dai principali centri di ricerca sulla sicurezza e utilizza l'intelligenza artificiale per trasformare bollettini complessi in report analitici comprensibili e azionabili.
🚀 Cosa puoi fare con questo tool
Monitoraggio Live: Aggiornamento automatico dei feed RSS ogni 5 minuti.
Analisi AI Istantanea: Generazione di riassunti esecutivi focalizzati su:
Vittima e attaccante.
Vettore di compromissione.
Impatto sui sistemi.
Estrazione Intelligence: Identificazione automatica di tecniche e tattiche (TTP) basate sul framework MITRE ATT&CK.
Chat con l'Esperto: Interroga l'IA per approfondire aspetti tecnici, strategie di mitigazione e indicatori di compromissione (IoC).
🌍 Fonti integrate
Il sistema monitora costantemente le seguenti sorgenti:
🇮🇹 CSIRT Italia (ACN)
🇮🇹 RedHotCyber
🌐 BleepingComputer
🌐 The Hacker News
🌐 CISA Cyber Alerts
🛠️ Tecnologie utilizzate
Frontend: Streamlit
AI Engine: Groq (LLaMA 3.1)
Intelligence Processing: LangChain
📝 Come contribuire o eseguire in locale
Per eseguire il progetto sulla tua macchina locale:
Installa i requisiti: pip install -r requirements.txt
Imposta la variabile d'ambiente GROQ_API_KEY con la tua chiave API.
Avvia l'app: streamlit run app.py
Progetto sviluppato per il miglioramento continuo della Situational Awareness in ambito Cyber Security.
