

from __future__ import annotations
import os, io, csv, base64, hashlib, hmac, secrets
from datetime import datetime
from typing import Optional, List, Tuple

import streamlit as st
import pandas as pd
from sqlmodel import SQLModel, Field, select, create_engine, Session
from sqlalchemy import delete

# ========================= Paths / DB ========================= #
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")
os.makedirs(DATA_DIR, exist_ok=True)

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)

def init_db():
    # Create tables ONCE per app run, AFTER models exist
    SQLModel.metadata.create_all(engine)

def get_session() -> Session:
    return Session(engine)

# ========================= Fix 1: Define models only once ========================= #
# ========================= Models (define once, allow re-import) ========================= #
class User(SQLModel, table=True):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password: str  # PBKDF2 (base64)
    created_at: str

class KPI(SQLModel, table=True):
    __tablename__ = "kpis"
    __table_args__ = {"extend_existing": True}
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="users.id")
    metric: str = Field(index=True)
    period: str = Field(index=True)  # YYYY-MM
    value: Optional[float] = None
    target: Optional[float] = None
    owner: Optional[str] = ""
    category: Optional[str] = ""
    unit: Optional[str] = ""
    notes: Optional[str] = ""
    created_at: str
    updated_at: str


# ========================= Auth (PBKDF2) ========================= #
def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    payload = salt + dk + iterations.to_bytes(4, "big")
    return base64.b64encode(payload).decode("utf-8")

def verify_password(password: str, stored: str) -> bool:
    raw = base64.b64decode(stored.encode("utf-8"))
    salt, rest = raw[:16], raw[16:]
    iterations = int.from_bytes(rest[-4:], "big")
    dk = rest[:-4]
    test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, test)

# ========================= Session state ========================= #
def require_auth():
    if "user" not in st.session_state:
        st.session_state.user = None
        st.session_state.user_id = None

# ========================= Helpers ========================= #
CSV_FIELDS = ["metric","period","value","target","owner","category","unit","notes"]

def norm_period(s: str) -> str:
    s = str(s).strip().replace("/", "-")
    if len(s) >= 7:
        y, m = s[:7].split("-")
        return f"{int(y):04d}-{int(m):02d}"
    return s

def parse_float(x) -> Optional[float]:
    try:
        if x is None or str(x).strip() == "":
            return None
        return float(str(x).replace(",", ""))
    except Exception:
        return None

def df_for_user(uid: int) -> pd.DataFrame:
    with get_session() as ses:
        rows = ses.exec(select(KPI).where(KPI.user_id == uid)).all()
    if not rows:
        return pd.DataFrame(columns=["id","metric","period","value","target","owner","category","unit","notes","created_at","updated_at"])
    df = pd.DataFrame([r.__dict__ for r in rows])
    return df.drop(columns={"_sa_instance_state"}, errors="ignore")

def compute_mom(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values(["metric","period"])
    df["value_mom"] = df.groupby("metric")["value"].pct_change()
    df["target_mom"] = df.groupby("metric")["target"].pct_change()
    return df

def compute_yoy(df: pd.DataFrame) -> pd.DataFrame:
    def prev_year(p):
        dtp = pd.Period(p, freq="M")
        return str(dtp - 12)
    base = df[["metric","period","value","target"]].rename(columns={"value":"value_prev","target":"target_prev"}).copy()
    base["period"] = base["period"].apply(prev_year)
    merged = df.merge(base, on=["metric","period"], how="left")
    merged["value_yoy"] = (merged["value"] / merged["value_prev"] - 1.0)
    merged["target_yoy"] = (merged["target"] / merged["target_prev"] - 1.0)
    return merged

# ========================= Auth views ========================= #
def login_view():
    st.title("📊 KPI Tracker (SQLite)")
    tabs = st.tabs(["Sign in", "Register"])

    with tabs[0]:
        with st.form("login", clear_on_submit=False):
            u = st.text_input("Username").strip().lower()
            p = st.text_input("Password", type="password")
            ok = st.form_submit_button("Sign in")
        if ok:
            with get_session() as ses:
                rec = ses.exec(select(User).where(User.username == u)).first()
            if not rec or not verify_password(p, rec.password):
                st.error("Invalid username or password.")
            else:
                st.session_state.user = rec.username
                st.session_state.user_id = rec.id
                st.rerun()

    with tabs[1]:
        with st.form("register", clear_on_submit=True):
            u = st.text_input("New username").strip().lower()
            p1 = st.text_input("Password", type="password")
            p2 = st.text_input("Confirm password", type="password")
            ok = st.form_submit_button("Create account")
        if ok:
            if not u or not p1:
                st.error("Username and password are required.")
            elif len(p1) < 6:
                st.error("Please use a longer password (≥ 6 chars).")
            elif p1 != p2:
                st.error("Passwords do not match.")
            else:
                with get_session() as ses:
                    exists = ses.exec(select(User).where(User.username == u)).first()
                    if exists:
                        st.error("That username is taken.")
                    else:
                        user = User(username=u, password=hash_password(p1), created_at=datetime.utcnow().isoformat(timespec="seconds"))
                        ses.add(user); ses.commit()
                        st.success("Registration successful. Please sign in.")

# ========================= Header ========================= #
def header():
    with st.container():
        left, mid, right = st.columns([3,2,2])
        with left: st.subheader("📊 KPI Tracker (SQLite)")
        with mid: st.caption(f"Signed in as **{st.session_state.user}**")
        with right:
            if st.button("Logout", use_container_width=True):
                st.session_state.user = None
                st.session_state.user_id = None
                st.rerun()
    st.divider()

# ========================= CSV import/export ========================= #
def export_csv_bytes(uid: int) -> bytes:
    df = df_for_user(uid)
    if df.empty:
        buf = io.StringIO()
        csv.DictWriter(buf, fieldnames=CSV_FIELDS).writeheader()
        return buf.getvalue().encode("utf-8")
    out = df[CSV_FIELDS].copy()
    return out.to_csv(index=False).encode("utf-8")

def import_csv(uid: int, file) -> Tuple[bool, str]:
    try:
        text = file.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        rows: List[KPI] = []
        now = datetime.utcnow().isoformat(timespec="seconds")
        for row in reader:
            metric = (row.get("metric") or "").strip()
            period = norm_period(row.get("period") or "")
            if not metric or not period:
                continue
            k = KPI(
                user_id=uid,
                metric=metric,
                period=period,
                value=parse_float(row.get("value")),
                target=parse_float(row.get("target")),
                owner=(row.get("owner") or "").strip(),
                category=(row.get("category") or "").strip(),
                unit=(row.get("unit") or "").strip(),
                notes=(row.get("notes") or "").strip(),
                created_at=now,
                updated_at=now,
            )
            rows.append(k)
        with get_session() as ses:
            ses.exec(delete(KPI).where(KPI.user_id == uid))
            for r in rows: ses.add(r)
            ses.commit()
        return True, f"Imported {len(rows)} rows."
    except Exception as e:
        return False, f"Failed to import CSV: {e}"

# ========================= Forms ========================= #
def add_kpi_form():
    st.subheader("Add KPI data point")
    with st.form("add_kpi", clear_on_submit=True):
        c1, c2 = st.columns(2)
        with c1:
            metric = st.text_input("Metric name*", placeholder="e.g., Net Sales")
            period = st.text_input("Period (YYYY-MM or YYYY-MM-DD)*", placeholder="2025-07")
            value = st.text_input("Actual value*", placeholder="12345.67")
        with c2:
            target = st.text_input("Target value", placeholder="15000")
            owner = st.text_input("Owner", placeholder="Sales")
        category = st.text_input("Category", placeholder="Revenue")
        unit = st.text_input("Unit", placeholder="USD / % / count")
        notes = st.text_area("Notes", placeholder="Optional notes…")
        ok = st.form_submit_button("Add row")
    if ok:
        if not metric.strip() or not period.strip():
            st.warning("Metric and period are required."); return
        now = datetime.utcnow().isoformat(timespec="seconds")
        with get_session() as ses:
            ses.add(KPI(
                user_id=st.session_state.user_id,
                metric=metric.strip(),
                period=norm_period(period),
                value=parse_float(value),
                target=parse_float(target),
                owner=owner.strip(),
                category=category.strip(),
                unit=unit.strip(),
                notes=notes.strip(),
                created_at=now,
                updated_at=now
            ))
            ses.commit()
        st.success("Row added."); st.rerun()

def edit_row_inline(row: dict):
    with st.expander(f"Edit: {row['metric']} @ {row['period']}", expanded=False):
        with st.form(f"edit-{row['id']}", clear_on_submit=False):
            c1, c2 = st.columns(2)
            with c1:
                metric = st.text_input("Metric", value=row["metric"])
                period = st.text_input("Period", value=row["period"])
                value = st.text_input("Actual value", value="" if pd.isna(row["value"]) else str(row["value"]))
            with c2:
                target = st.text_input("Target", value="" if pd.isna(row["target"]) else str(row["target"]))
                owner = st.text_input("Owner", value=row.get("owner",""))
            category = st.text_input("Category", value=row.get("category",""))
            unit = st.text_input("Unit", value=row.get("unit",""))
            notes = st.text_area("Notes", value=row.get("notes",""))
            cols = st.columns(3)
            save = cols[0].form_submit_button("Save")
            delete_btn = cols[1].form_submit_button("Delete")
            cancel = cols[2].form_submit_button("Cancel")
        if save:
            with get_session() as ses:
                obj = ses.get(KPI, int(row["id"]))
                if obj and obj.user_id == st.session_state.user_id:
                    obj.metric = metric.strip()
                    obj.period = norm_period(period)
                    obj.value = parse_float(value)
                    obj.target = parse_float(target)
                    obj.owner = owner.strip()
                    obj.category = category.strip()
                    obj.unit = unit.strip()
                    obj.notes = notes.strip()
                    obj.updated_at = datetime.utcnow().isoformat(timespec="seconds")
                    ses.add(obj); ses.commit()
            st.success("Saved."); st.rerun()
        if delete_btn:
            with get_session() as ses:
                obj = ses.get(KPI, int(row["id"]))
                if obj and obj.user_id == st.session_state.user_id:
                    ses.delete(obj); ses.commit()
            st.success("Deleted."); st.rerun()
        if cancel:
            pass

# ========================= Dashboard ========================= #
def header_bar():
    header()
    with st.expander("CSV import/export", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            up = st.file_uploader("Import CSV", type=["csv"])
            if up is not None:
                ok, msg = import_csv(st.session_state.user_id, up)
                st.success(msg) if ok else st.error(msg)
        with c2:
            if st.button("Export CSV"):
                st.download_button(
                    "Download kpis.csv",
                    data=export_csv_bytes(st.session_state.user_id),
                    file_name="kpis.csv",
                    mime="text/csv",
                    use_container_width=True
                )

def dashboard():
    header_bar()
    add_kpi_form()

    df = df_for_user(st.session_state.user_id)
    if df.empty:
        st.info("No data yet. Import a CSV or add a row above.")
        return

    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df["target"] = pd.to_numeric(df["target"], errors="coerce")
    df["period"] = df["period"].astype(str)
    df["variance"] = df["value"] - df["target"]
    df["pct_to_target"] = df["value"] / df["target"]

    # Filters
    st.subheader("Filters")
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        metrics = sorted(df["metric"].dropna().unique().tolist())
        pick_metrics = st.multiselect("Metric", metrics, default=metrics[: min(5, len(metrics))])
    with f2:
        owners = sorted([x for x in df["owner"].dropna().unique().tolist() if x])
        pick_owners = st.multiselect("Owner", owners)
    with f3:
        cats = sorted([x for x in df["category"].dropna().unique().tolist() if x])
        pick_cats = st.multiselect("Category", cats)
    with f4:
        periods = sorted(df["period"].unique().tolist())
        start = st.selectbox("From", periods, index=0) if periods else None
        end = st.selectbox("To", periods, index=len(periods)-1) if periods else None

    filtered = df.copy()
    if pick_metrics: filtered = filtered[filtered["metric"].isin(pick_metrics)]
    if pick_owners:  filtered = filtered[filtered["owner"].isin(pick_owners)]
    if pick_cats:    filtered = filtered[filtered["category"].isin(pick_cats)]
    if start and end: filtered = filtered[(filtered["period"] >= start) & (filtered["period"] <= end)]

    # Cards
    latest_period = sorted(filtered["period"].unique())[-1] if len(filtered) else None
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Data points", value=len(filtered))
    with c2:
        if latest_period:
            latest = filtered[filtered["period"] == latest_period]
            on_target = (latest["value"] >= latest["target"]).sum()
            st.metric(f"On‑target ({latest_period})", value=f"{on_target}/{len(latest)}")
        else:
            st.metric("On‑target", value="—")
    with c3:
        if latest_period:
            latest = filtered[filtered["period"] == latest_period]
            avg_pct = (latest["value"] / latest["target"]).replace([pd.NA, pd.NaT], pd.NA).dropna().mean()
            st.metric("Avg % to target", value=f"{(avg_pct*100):.1f}%" if pd.notna(avg_pct) else "—")
        else:
            st.metric("Avg % to target", value="—")

    with c4:
        if latest_period:
            latest = filtered[filtered["period"] == latest_period]
            avg_var = (latest["value"] - latest["target"]).mean()
            st.metric("Avg variance", value=f"{avg_var:.2f}" if pd.notna(avg_var) else "—")
        else:
            st.metric("Avg variance", value="—")

    st.subheader("KPI Table")
    st.dataframe(filtered, use_container_width=True)

    st.subheader("Edit / Delete rows")
    for _, row in filtered.iterrows():
        edit_row_inline(row)

# ========================= Main ========================= #
def main():
    init_db()
    require_auth()
    if not st.session_state.user:
        login_view()
    else:
        dashboard()

if __name__ == "__main__":
    main()
# This is the entry point for the Streamlit app