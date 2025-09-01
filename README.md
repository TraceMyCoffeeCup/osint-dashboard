# 🔍 OSINT Dashboard (Console)

Toolkit investigativo in **Python** sviluppato come parte della tesi triennale  
**“Criminologia Informatica e OSINT: Tecniche di Investigazione Digitale”**.

---

## 📌 Cos’è
L’**OSINT Dashboard** è un **mini–toolkit interattivo da console** che raccoglie strumenti fondamentali per un’indagine digitale:

1. **Crea profilo digitale** → estrae indicatori (email, handle social, URL, domini, IP, telefoni IT, IBAN).  
2. **Verifica catena di custodia** → calcola hash (SHA256/MD5) di file o directory, produce inventario e verifica integrità.  
3. **Crea timeline** → ordina eventi da input manuale/CSV/JSON con normalizzazione temporale (UTC).  
4. **Analizza dataset sospetto** → effettua un triage per individuare PII/IOC (email, IP, hash, token, IBAN, carte valide con Luhn, segreti).  

---

## 🎯 A cosa serve
Il tool simula un **workflow OSINT/forense**:

- **Profilazione** → costruzione di un profilo digitale.  
- **Conservazione** → mantenere la catena di custodia.  
- **Ricostruzione** → timeline investigativa.  
- **Triage** → analisi preliminare di dataset sospetti.  

---

## ⚙️ Installazione
### Requisiti
- **Python 3.9+**
