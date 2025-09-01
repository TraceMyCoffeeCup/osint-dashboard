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

🖥️ Esempi d’uso
1️⃣ Crea profilo digitale

Input

Soggetto: Mario Rossi
Email: mario.rossi@mail.com
Twitter: @marior
Sito: https://rossi-investigazioni.it


Output

# Profilo Digitale — Mario Rossi
- Email: mario.rossi@mail.com
- Handle: @marior
- URL: https://rossi-investigazioni.it
- Dominio: rossi-investigazioni.it

2️⃣ Verifica catena di custodia

Input

Percorso: documento.docx


Output

# Catena di Custodia — Inventario
- File: documento.docx
- SHA256: 3f785e1a...
- MD5: 5d41402a...
- Dimensione: 152 KB

3️⃣ Crea timeline

Input

2025-08-28 15:30:00 | Accesso sospetto da IP 192.168.1.10 | Log server
2025-08-28 15:45:00 | Reset password account Rossi | Gmail


Output

# Timeline
| Data Orig. | UTC | Evento | Fonte |
|------------|-----|--------|-------|
| 2025-08-28 15:30:00 | 2025-08-28T13:30:00Z | Accesso sospetto... | Log server |
| 2025-08-28 15:45:00 | 2025-08-28T13:45:00Z | Reset password...  | Gmail |

4️⃣ Analizza dataset sospetto

Input

Percorso: dump_cartella


Output

# Dataset Triage Report
- Root: dump_cartella
- Elementi analizzati: 42

### dump1.txt
- MIME: text/plain
- Email: mario@esempio.it
- IBAN IT: IT60X0542811101000000123456
- Secret-like: api_key=ABCD1234...
- Preview: `Login: mario | Pwd: Segreto123`
