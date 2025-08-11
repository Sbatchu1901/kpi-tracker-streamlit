

# 📊 KPI Tracker – Python + Streamlit + SQLite

A lightweight **KPI tracking dashboard** with:

* 🔒 Secure user authentication
* 📥 CSV import/export
* ✏️ Inline add/edit/delete
* 📊 KPI summary cards & filtering

## 🚀 Features

* User-specific KPI storage (SQLite)
* Secure password hashing
* Filters by metric, owner, category, date
* CSV import/export for bulk data
* Real-time summary cards (variance, % to target, on-target count)

## 🛠️ Tech Stack

* Python
* Streamlit
* SQLModel / SQLAlchemy
* Pandas
* SQLite

## 📂 Project Structure

```
kpi-tracker/
├── app.py
├── requirements.txt
├── README.md
└── sample_data.csv
```

## ⚡ Installation

```bash
git clone https://github.com/<your-username>/kpi-tracker-streamlit.git
cd kpi-tracker
pip install -r requirements.txt
streamlit run app.py
```


