import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";
const categories = [
  ["catcalling", "Catcalling"], ["following", "Following"],
  ["loitering_blocking", "Loitering / Blocking"], ["threatening", "Threatening behaviour"],
  ["unwanted_approach", "Unwanted approach"], ["other", "Other"],
];
const demoPolice = "POLICE-042";
const authorityFallback = "Malvan Authority · Malvan Taluka";

function formatApiError(detail, fallback = "Request failed") {
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    return detail.map(item => {
      if (typeof item === "string") return item;
      if (item?.msg) {
        const where = Array.isArray(item.loc) ? item.loc.join(" → ") : "";
        return where ? `${where}: ${item.msg}` : item.msg;
      }
      try { return JSON.stringify(item); } catch { return "Validation error"; }
    }).join("; ");
  }
  if (detail && typeof detail === "object") {
    if (detail.message) return String(detail.message);
    if (detail.error) return typeof detail.error === "string" ? detail.error : JSON.stringify(detail.error);
    try { return JSON.stringify(detail); } catch { return fallback; }
  }
  return fallback;
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const isForm = typeof FormData !== "undefined" && options.body instanceof FormData;
  if (!isForm && options.body != null && typeof options.body === "object" && !(options.body instanceof Blob)) options.body = JSON.stringify(options.body);
  if (!isForm && options.body != null && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const r = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(formatApiError(d.detail, `Request failed (${r.status})`));
  return d;
}
function authApi(path, tokenValue, options = {}) { return api(path, { ...options, headers: { ...(options.headers || {}), Authorization: `Bearer ${tokenValue}` } }); }
function useTransientError() {
  const [message, setMessage] = useState("");
  const timerRef = useRef(null);
  const showError = (value, duration = 4500) => {
    const message = value instanceof Error ? value.message : String(value || "");
    setMessage(message);
    if (timerRef.current) clearTimeout(timerRef.current);
    if (message) timerRef.current = setTimeout(() => setMessage(""), duration);
  };
  const clearError = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    setMessage("");
  };
  useEffect(() => () => timerRef.current && clearTimeout(timerRef.current), []);
  return [message, showError, clearError];
}

function token() {
  let t = localStorage.getItem("safeline-token");
  if (!t) { t = crypto.randomUUID() + crypto.randomUUID(); localStorage.setItem("safeline-token", t); }
  return t;
}

const OFFLINE_QUEUE_KEY = "safeline-offline-reports";
const OFFLINE_SPOTS_KEY = "safeline-spots-cache";

function useOnlineStatus() {
  const [online, setOnline] = useState(() => navigator.onLine);
  useEffect(() => {
    const on = () => setOnline(true);
    const off = () => setOnline(false);
    window.addEventListener("online", on);
    window.addEventListener("offline", off);
    return () => {
      window.removeEventListener("online", on);
      window.removeEventListener("offline", off);
    };
  }, []);
  return online;
}

function readOfflineQueue() {
  try { return JSON.parse(localStorage.getItem(OFFLINE_QUEUE_KEY) || "[]"); }
  catch { return []; }
}
function writeOfflineQueue(items) {
  localStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(items.slice(-50)));
}
function queueOfflineReport(payload) {
  const queue_id = `OFF-${Date.now().toString(36).toUpperCase()}-${crypto.randomUUID().slice(0, 6).toUpperCase()}`;
  const item = { queue_id, queued_at: new Date().toISOString(), payload: { ...payload, offline_queue_id: queue_id } };
  writeOfflineQueue([...readOfflineQueue(), item]);
  return item;
}
function isNetworkFailure(error) {
  return !navigator.onLine || error instanceof TypeError ||
    /failed to fetch|network|load failed|offline|fetch/i.test(String(error?.message || error));
}
function offlineReportView(item) {
  const p = item.payload || {};
  return {
    id: item.queue_id,
    category: p.category,
    category_label: categories.find(c => c[0] === p.category)?.[1] || p.category,
    location_label: p.location_label || "Location unavailable",
    received_at: item.queued_at,
    tier: "WATCH",
    status: "received",
    location_source: p.location_source || "manual",
    offline_capture: true,
  };
}
function readCachedSpots() {
  try { return JSON.parse(localStorage.getItem(OFFLINE_SPOTS_KEY) || "[]"); }
  catch { return []; }
}
function cacheSpots(spots) {
  if (Array.isArray(spots) && spots.length) {
    localStorage.setItem(OFFLINE_SPOTS_KEY, JSON.stringify(spots));
  }
}
let offlineFlushInFlight = null;
async function flushOfflineQueue() {
  if (offlineFlushInFlight) return offlineFlushInFlight;
  offlineFlushInFlight = (async () => {
  const queue = readOfflineQueue();
  if (!queue.length || !navigator.onLine) return 0;
  const remaining = [];
  let sent = 0;
  for (const item of queue) {
    try {
      await api("/api/reports/offline-relay", { method: "POST", body: item.payload });
      sent += 1;
    } catch {
      remaining.push(item);
    }
  }
  writeOfflineQueue(remaining);
  return sent;
  })();
  try { return await offlineFlushInFlight; }
  finally { offlineFlushInFlight = null; }
}

function themeInit() { return localStorage.getItem("safeline-theme") || "light"; }
function useTheme() {
  const [theme, setTheme] = useState(themeInit);
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem("safeline-theme", theme); }, [theme]);
  return [theme, () => setTheme(t => t === "light" ? "dark" : "light")];
}

function Shell({ mode, children, onSwitch, onBrand }) {
  const [theme, toggleTheme] = useTheme();
  return <div className="app">
    <header className="topbar">
      <button className="brand" onClick={onBrand || onSwitch}><span className="brand-mark">S</span><span>SafeLine</span></button>
      <div className="top-right">
        <span className="mode-pill">{mode === "Citizen" ? "Public safety" : "Safety operations"}</span>
        <button className="icon-button" title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"} onClick={toggleTheme}>{theme === "light" ? "◐" : "☼"}</button>
        {mode === "Authority" && <button className="mode-link" onClick={onSwitch}>Citizen view</button>}
      </div>
    </header>
    {children}
  </div>;
}

function distanceM(a,b){if(!a||!b)return Infinity;const R=6371000,p1=a.lat*Math.PI/180,p2=b.lat*Math.PI/180,dp=(b.lat-a.lat)*Math.PI/180,dl=(b.lng-a.lng)*Math.PI/180;const x=Math.sin(dp/2)**2+Math.cos(p1)*Math.cos(p2)*Math.sin(dl/2)**2;return 2*R*Math.asin(Math.sqrt(x))}
function useLiveLocation(spots = []) {
  const [location, setLocation] = useState({
    status: "detecting",
    lat: null,
    lng: null,
    label: "Detecting your location…",
    accuracy: null,
    nearestSpotId: null,
    nearestSpotName: null,
  });

  useEffect(() => {
    if (!navigator.geolocation) {
      setLocation({
        status: "unavailable",
        lat: null,
        lng: null,
        label: "Location unavailable — choose a reporting spot",
        accuracy: null,
        nearestSpotId: null,
        nearestSpotName: null,
      });
      return;
    }

    let active = true;
    let addressController = null;

    const nearestSpot = (lat, lng) =>
      spots
        .map((spot) => ({
          ...spot,
          distance: distanceM(
            { lat, lng },
            { lat: spot.latitude, lng: spot.longitude }
          ),
        }))
        .filter((spot) => spot.distance <= 250)
        .sort((a, b) => a.distance - b.distance)[0];

    // Reverse geocoding is ONLY a label enhancement. GPS becomes ready first.
    const reverseLookup = async (lat, lng) => {
      try {
        addressController?.abort();
        addressController = new AbortController();
        const timeout = setTimeout(() => addressController?.abort(), 2500);

        const response = await fetch(
          `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lng)}&zoom=18&addressdetails=1`,
          {
            headers: { Accept: "application/json" },
            signal: addressController.signal,
          }
        );

        clearTimeout(timeout);
        if (!response.ok) return;
        const data = await response.json();
        if (!active || !data) return;

        const a = data.address || {};
        const label = [
          a.road || a.pedestrian || a.neighbourhood,
          a.suburb || a.town || a.city || a.village,
          a.state,
        ].filter(Boolean).slice(0, 3).join(", ") || data.display_name;

        if (label) {
          setLocation(current => ({ ...current, label }));
        }
      } catch {
        // Coordinates are already usable. A readable address is optional.
      }
    };

    const success = (position) => {
      if (!active) return;

      const { latitude: lat, longitude: lng, accuracy } = position.coords;
      const nearest = nearestSpot(lat, lng);

      // IMPORTANT: make GPS ready immediately. Do not wait for reverse geocoding.
      setLocation({
        status: "ready",
        lat,
        lng,
        accuracy,
        label: nearest
          ? nearest.name
          : `Current location · ±${Math.round(accuracy || 0)}m`,
        nearestSpotId: nearest?.id || null,
        nearestSpotName: nearest?.name || null,
      });

      if (!nearest) reverseLookup(lat, lng);
    };

    const failure = (error) => {
      if (!active) return;

      if (error.code === 1) {
        setLocation({
          status: "denied",
          lat: null,
          lng: null,
          label: "Location permission denied — choose a reporting spot",
          accuracy: null,
          nearestSpotId: null,
          nearestSpotName: null,
        });
      } else {
        setLocation({
          status: "unavailable",
          lat: null,
          lng: null,
          label: "Could not detect location — choose a reporting spot",
          accuracy: null,
          nearestSpotId: null,
          nearestSpotName: null,
        });
      }
    };

    // First ask for a cached/coarse fix. This is usually much faster.
    navigator.geolocation.getCurrentPosition(
      success,
      () => {
        // Fall back to a fresh high-accuracy fix only if the fast request fails.
        navigator.geolocation.getCurrentPosition(
          success,
          failure,
          { enableHighAccuracy: true, maximumAge: 10000, timeout: 10000 }
        );
      },
      { enableHighAccuracy: false, maximumAge: 30000, timeout: 5000 }
    );

    return () => {
      active = false;
      addressController?.abort();
    };
  }, [spots]);

  return location;
}
function LocationBar({ location }) {
  const ready = location.status === "ready";
  return <div className="location-bar"><span className={`location-dot ${ready ? "ready" : ""}`}></span><div><span className="eyebrow">CURRENT LOCATION</span><strong>{location.label}</strong>{location.accuracy && <small>Used for this report only · ±{Math.round(location.accuracy)}m</small>}</div><span className="location-state">{ready ? "LIVE" : location.status === "denied" ? "OFF" : "…"}</span></div>;
}

function spotIdForLocation(spots,location){if(!location?.lat)return null;const nearest=spots.map(x=>({...x,distance:distanceM({lat:location.lat,lng:location.lng},{lat:x.latitude,lng:x.longitude})})).filter(x=>x.distance<=250).sort((a,b)=>a.distance-b.distance)[0];return nearest?.id||null}
function Citizen({ go }) {
  const online = useOnlineStatus();
  const [spots, setSpots] = useState(() => readCachedSpots());
  const [spotChoice, setSpotChoice] = useState("");
  const [spotSearch, setSpotSearch] = useState("");
  const [manualLocation, setManualLocation] = useState("");
  const [editingReportId, setEditingReportId] = useState(null);
  const [undoUntil, setUndoUntil] = useState(0);
  const [undoSeconds, setUndoSeconds] = useState(0);
  const location = useLiveLocation(spots);
  const [step, setStep] = useState("home");
  const [cat, setCat] = useState("");
  const [when, setWhen] = useState("just_now");
  const [who, setWho] = useState("self");
  const [still, setStill] = useState(false);
  const [note, setNote] = useState("");
  const [receipt, setReceipt] = useState(null);
  const [statusId, setStatusId] = useState("");
  const [statusResult, setStatusResult] = useState(null);
  const [past, setPast] = useState([]);
  const [helpResult, setHelpResult] = useState(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [hub, setHub] = useState(false);
  const [planner, setPlanner] = useState(false);
  const [contacts, setContacts] = useState(() => JSON.parse(localStorage.getItem("safeline-contacts") || "[]"));
  const [journey, setJourney] = useState(() => JSON.parse(localStorage.getItem("safeline-journey") || "null"));
  const [journeyLeft, setJourneyLeft] = useState(0);
  const [sirenOn, setSirenOn] = useState(false);
  const audioRef = useRef(null);

  const selectedSpot = spots.find(s => s.id === spotChoice) || null;
  const gpsAvailable = online && location.lat != null;
  const filteredSpots = useMemo(() => {
    const q = spotSearch.trim().toLowerCase();
    if (!q) return spots;
    return spots.filter(s => `${s.name || ""} ${s.zone_name || ""}`.toLowerCase().includes(q));
  }, [spots, spotSearch]);
  const locationReady = Boolean(selectedSpot || gpsAvailable || manualLocation.trim());

  const resetReportDraft = () => {
    setEditingReportId(null);
    setSpotChoice("");
    setSpotSearch("");
    setManualLocation("");
    setCat("");
    setWhen("just_now");
    setWho("self");
    setStill(false);
    setNote("");
    setReceipt(null);
    setStatusId("");
    setStatusResult(null);
    setErr("");
    setLoading(false);
  };

  const startReport = () => {
    resetReportDraft();
    // Online: GPS is captured automatically; go straight to the category.
    // Offline: cached/manual location selection is required before the category.
    setStep(online ? "category" : "location");
  };

  const refreshPast = async () => {
    const queued = readOfflineQueue().map(offlineReportView);
    try {
      const response = await api(`/api/reports/mine/${encodeURIComponent(token())}`);
      const server = Array.isArray(response) ? response : [];
      const seen = new Set();
      const merged = [];
      for (const r of server) { if (!seen.has(r.id)) { seen.add(r.id); merged.push(r); } }
      for (const q of queued) {
        const duplicate = merged.some(r => r.category === q.category && r.location_label === q.location_label && Math.abs(new Date(r.received_at).getTime() - new Date(q.received_at).getTime()) < 120000);
        if (!duplicate && !seen.has(q.id)) { seen.add(q.id); merged.push(q); }
      }
      merged.sort((a,b)=>new Date(b.received_at).getTime()-new Date(a.received_at).getTime());
      setPast(merged.slice(0,25));
    } catch { setPast(queued); }
  };

  useEffect(() => {
    let active = true;
    api("/api/spots").then(data => {
      if (!active || !Array.isArray(data)) return;
      cacheSpots(data);
      setSpots(data);
    }).catch(() => {
      if (active) setSpots(readCachedSpots());
    });
    refreshPast();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const flush = async () => {
      const sent = await flushOfflineQueue();
      if (sent) await refreshPast();
    };
    if (online) flush();
    window.addEventListener("online", flush);
    return () => window.removeEventListener("online", flush);
  }, [online]);

  useEffect(() => {
    if (!undoUntil) return;
    const id = setInterval(() => {
      const left = Math.max(0, Math.ceil((undoUntil - Date.now()) / 1000));
      setUndoSeconds(left);
      if (left === 0) {
        setUndoUntil(0);
        clearInterval(id);
      }
    }, 200);
    return () => clearInterval(id);
  }, [undoUntil]);

  useEffect(() => {
    if (!journey) return;
    const id = setInterval(() => {
      const left = Math.max(0, Math.floor((new Date(journey.nextCheck).getTime() - Date.now()) / 1000));
      setJourneyLeft(left);
      if (left === 0) {
        setJourney(null);
        localStorage.removeItem("safeline-journey");
        alert("SafeLine check-in time reached. If you are not safe, use the Emergency Hub or call 112.");
      }
    }, 1000);
    return () => clearInterval(id);
  }, [journey]);

  const getLocationPayload = () => {
    if (selectedSpot) {
      return {
        spot_id: selectedSpot.id,
        latitude: selectedSpot.latitude,
        longitude: selectedSpot.longitude,
        location_label: selectedSpot.name,
        location_source: "registered",
        location_consent: true,
      };
    }
    if (gpsAvailable) {
      return {
        spot_id: null,
        latitude: location.lat,
        longitude: location.lng,
        location_label: location.nearestSpotName || location.label || "Current location",
        location_source: "gps",
        location_consent: true,
      };
    }
    if (manualLocation.trim()) {
      return {
        spot_id: null,
        latitude: null,
        longitude: null,
        location_label: manualLocation.trim(),
        location_source: "manual",
        location_consent: false,
      };
    }
    return {
      spot_id: null,
      latitude: null,
      longitude: null,
      location_label: null,
      location_source: "manual",
      location_consent: false,
    };
  };

  const submitPayload = () => ({
    ...getLocationPayload(),
    category: cat,
    happened_when: when,
    reporter_type: who,
    still_happening: still,
    reporter_token: token(),
    note: note.trim() || null,
  });

  const submit = async () => {
    if (!locationReady) {
      setErr("Choose a registered location or enter a public location/landmark before submitting.");
      return;
    }
    setLoading(true);
    setErr("");
    try {
      const payload = submitPayload();
      let result;
      if (!online) {
        const q = queueOfflineReport(payload);
        result = {
          report_id: q.queue_id,
          location_label: payload.location_label,
          category: categories.find(x => x[0] === cat)?.[1] || cat,
          received_at: q.queued_at,
          status: "received",
          offline: true,
        };
      } else {
        try {
          result = await api("/api/reports", { method: "POST", body: payload });
        } catch (e) {
          if (!isNetworkFailure(e)) throw e;
          const q = queueOfflineReport(payload);
          result = {
            report_id: q.queue_id,
            location_label: payload.location_label,
            category: categories.find(x => x[0] === cat)?.[1] || cat,
            received_at: q.queued_at,
            status: "received",
            offline: true,
          };
        }
      }
      setReceipt(result);
      setStatusId(result.report_id);
      setStep("receipt");
      setUndoUntil(result.offline ? 0 : Date.now() + 5000);
      setUndoSeconds(result.offline ? 0 : 5);
      refreshPast();
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  const quickSubmit = async category => {
    setCat(category);
    setErr("");

    // Category shortcuts are only reachable after the explicit location step.
    // Keep this guard for keyboard/direct invocation so an old location can never
    // be silently reused.
    if (!locationReady) {
      if (!online) {
        setStep("location");
        setErr("Choose a reporting location before selecting a category.");
      } else {
        setErr("SafeLine could not capture your current location yet. Please allow location access and try again.");
      }
      return;
    }

    setLoading(true);
    try {
      const payload = {
        ...getLocationPayload(),
        category,
        happened_when: "just_now",
        reporter_type: "self",
        still_happening: false,
        reporter_token: token(),
        note: null,
      };
      let result;
      if (!online) {
        const q = queueOfflineReport(payload);
        result = {
          report_id: q.queue_id,
          location_label: payload.location_label,
          category: categories.find(x => x[0] === category)?.[1] || category,
          received_at: q.queued_at,
          status: "received",
          offline: true,
        };
      } else {
        try {
          result = await api("/api/reports", { method: "POST", body: payload });
        } catch (e) {
          if (!isNetworkFailure(e)) throw e;
          const q = queueOfflineReport(payload);
          result = {
            report_id: q.queue_id,
            location_label: payload.location_label,
            category: categories.find(x => x[0] === category)?.[1] || category,
            received_at: q.queued_at,
            status: "received",
            offline: true,
          };
        }
      }
      setReceipt(result);
      setStatusId(result.report_id);
      setStep("receipt");
      setUndoUntil(result.offline ? 0 : Date.now() + 5000);
      setUndoSeconds(result.offline ? 0 : 5);
      refreshPast();
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  const undoLastReport = async () => {
    if (!receipt) return;
    if (receipt.offline) {
      writeOfflineQueue(readOfflineQueue().filter(x => x.queue_id !== receipt.report_id));
      setUndoUntil(0);
      setReceipt(null);
      setStatusResult(null);
      setStep("home");
      setErr("");
      refreshPast();
      return;
    }
    try {
      await api(`/api/reports/${receipt.report_id}/undo`, { method: "POST", body: { reporter_token: token() } });
      setUndoUntil(0);
      setReceipt(null);
      setStatusResult(null);
      setStep("home");
      setErr("");
      refreshPast();
    } catch (e) {
      setErr(e.message);
    }
  };

  const addContext = () => { setEditingReportId(receipt?.report_id || null); setStep("context"); };
  const saveContext = async () => {
    if (!editingReportId || String(editingReportId).startsWith("OFF-")) {
      setErr("Offline reports can receive additional context after they sync.");
      return;
    }
    setLoading(true);
    try {
      await api(`/api/reports/${editingReportId}/context`, {
        method: "POST",
        body: { reporter_token: token(), happened_when: when, reporter_type: who, still_happening: still, note: note.trim() || null }
      });
      setEditingReportId(null);
      setStep("receipt");
      setReceipt(r => ({ ...r }));
      refreshPast();
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  const openTrustedSms = message => {
    const c = contacts[0];
    if (!c) { setStep("contacts"); setErr("Add a trusted contact first."); return false; }
    window.location.href = `sms:${encodeURIComponent(c.phone)}?body=${encodeURIComponent(message)}`;
    return true;
  };

  const shareEmergency = async (kind = "location") => {
    setLoading(true); setErr("");
    try {
      let label = location.label;
      let mapUrl = location.lat != null && location.lng != null
        ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(`${location.lat},${location.lng}`)}`
        : "";

      if (location.lat != null && !location.nearestSpotId && (!label || label.includes("Resolving") || label.includes("Current GPS"))) {
        try {
          const r = await fetch(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${encodeURIComponent(location.lat)}&lon=${encodeURIComponent(location.lng)}&zoom=18&addressdetails=1`, { headers: { Accept: "application/json" } });
          const x = await r.json();
          const a = x.address || {};
          label = [a.road || a.pedestrian || a.neighbourhood, a.suburb || a.town || a.city || a.village, a.state].filter(Boolean).slice(0, 3).join(", ") || x.display_name || `Coordinates ${location.lat.toFixed(5)}, ${location.lng.toFixed(5)}`;
        } catch {
          label = `Coordinates ${location.lat.toFixed(5)}, ${location.lng.toFixed(5)}`;
        }
      }

      const contactName = contacts[0]?.name || "Trusted contact";
      const message = kind === "message"
        ? `SafeLine safety message from ${contactName}.${label ? ` Location: ${label}.` : " I need help."}${mapUrl ? ` Map: ${mapUrl}` : ""}`
        : `SafeLine emergency alert.${label ? ` Location: ${label}.` : " I need help."}${mapUrl ? ` Map: ${mapUrl}.` : ""}`;

      // Emergency support tools must remain usable without internet. If the API is
      // unavailable, the device SMS composer is still a valid cellular fallback.
      if (!online) {
        openTrustedSms(message);
        setHelpResult({ request_id: "OFFLINE", location_label: label || "Location unavailable", offline: true, message: "Safety message prepared in the device SMS composer." });
        return;
      }

      if (location.lat == null) {
        if (kind === "message") {
          openTrustedSms(message);
          setHelpResult({ request_id: "LOCAL", location_label: "Location not available", offline: true, message: "Safety message prepared without a location point." });
          return;
        }
        setErr("Your current location is not ready yet.");
        return;
      }

      const x = await api("/api/help-now", { method: "POST", body: { latitude: location.lat, longitude: location.lng, location_label: label, kind, map_url: mapUrl } });
      setHelpResult({ ...x, location_label: label, map_url: mapUrl });
      openTrustedSms(kind === "message" ? message : `${message} Request: ${x.request_id}. Please check on me.`);
    } catch (e) {
      // If the network drops while using an online session, preserve the offline SOS path.
      if (isNetworkFailure(e)) {
        const contactName = contacts[0]?.name || "Trusted contact";
        const fallback = `SafeLine safety alert from ${contactName}.${location.label ? ` Location: ${location.label}.` : " I need help."}`;
        openTrustedSms(fallback);
        setHelpResult({ request_id: "OFFLINE", location_label: location.label || "Location unavailable", offline: true, message: "Safety message prepared in the device SMS composer." });
      } else {
        setErr(e.message);
      }
    } finally {
      setLoading(false);
    }
  };

  const requestHelp = () => shareEmergency("location");
  const shareSafetyMessage = () => shareEmergency("message");
  const checkStatus = async id => {
    const value = (id || statusId).trim().toUpperCase();
    if (!value) return;
    if (value.startsWith("OFF-")) {
      const item = readOfflineQueue().find(x => x.queue_id === value);
      setStatusResult(item ? { location_label: item.payload.location_label, tier: "WATCH", status: "received", action_type: "Waiting for connection" } : null);
      return;
    }
    try { setStatusResult(await api(`/api/reports/${value}`)); }
    catch (e) { setErr(e.message); }
  };

  const reset = () => {
    setStep("home");
    setCat("");
    setWhen("just_now");
    setWho("self");
    setStill(false);
    setNote("");
    setSpotChoice("");
    setSpotSearch("");
    setManualLocation("");
    setReceipt(null);
    setStatusId("");
    setStatusResult(null);
    setEditingReportId(null);
    setErr("");
    setLoading(false);
  };

  const toggleSiren = () => {
    if (sirenOn) { audioRef.current?.stop(); audioRef.current = null; setSirenOn(false); return; }
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sawtooth"; osc.frequency.value = 880; gain.gain.value = 0.08;
    osc.connect(gain); gain.connect(ctx.destination); osc.start();
    audioRef.current = { stop: () => { osc.stop(); ctx.close(); } };
    setSirenOn(true);
    setTimeout(() => { if (audioRef.current) { audioRef.current.stop(); audioRef.current = null; setSirenOn(false); } }, 4500);
  };
  const fakeCall = () => { setHub(false); setStep("fakecall"); };
  const saveContact = (name, phone) => {
    if (!name.trim() || !phone.trim()) return;
    const next = [...contacts, { id: crypto.randomUUID(), name: name.trim(), phone: phone.trim() }];
    setContacts(next); localStorage.setItem("safeline-contacts", JSON.stringify(next));
  };
  const removeContact = id => {
    const next = contacts.filter(c => c.id !== id);
    setContacts(next); localStorage.setItem("safeline-contacts", JSON.stringify(next));
  };
  const startJourney = mins => {
    const next = { startedAt: new Date().toISOString(), nextCheck: new Date(Date.now() + mins * 60000).toISOString(), minutes: mins };
    setJourney(next); localStorage.setItem("safeline-journey", JSON.stringify(next));
  };
  const checkIn = () => {
    if (!journey) return;
    const next = { ...journey, nextCheck: new Date(Date.now() + journey.minutes * 60000).toISOString() };
    setJourney(next); localStorage.setItem("safeline-journey", JSON.stringify(next));
  };

  return <Shell mode="Citizen" onBrand={() => { reset(); go("/"); }} onSwitch={() => go("/authority")}>
    <main className="citizen">
      <div className="hero citizen-hero">
        <div>
          <span className="eyebrow pink">PUBLIC SAFETY · EARLY WARNING</span>
          <h1>{step === "home" ? <>A warning sign<br/><em>should not be invisible.</em></> : step === "receipt" ? "Your report is in the system" : step === "help" ? "Emergency support" : step === "planner" ? "Plan before you go" : step === "fakecall" ? "Incoming call" : step === "past" ? "Your past reports" : "Quick report"}</h1>
          <p>Report a warning sign in seconds. SafeLine turns separate signals into explainable patterns and tracks the preventive action that follows.</p>
        </div>
        <LocationBar location={location}/>
      </div>

      {!online && <div className="offline-banner"><strong>OFFLINE MODE</strong><span>GPS may still work, but reports are saved on this device until the connection returns.</span></div>}

      {step === "home" && <>
        <div className="location-banner">
          <div><span className="live-ring"></span><div><strong>{gpsAvailable ? "Location detected" : selectedSpot ? selectedSpot.name : "Location needs your choice"}</strong><span>{gpsAvailable ? location.label : selectedSpot ? "Registered reporting location" : "Choose a registered location when you report"}</span></div></div>
          <span className="privacy-tag">NO ACCOUNT · ONE POINT ONLY</span>
        </div>
        <div className="quick-actions">
          <button className="big-action report-action" onClick={startReport}>
            <span className="floating-key">REPORT</span><strong>Something felt unsafe</strong><span>Quick report · no account · current location attached automatically</span><b>Report now →</b>
          </button>
          <button className="big-action emergency-action" onClick={() => { setHub(true); setErr(""); }}>
            <span className="floating-key">SOS</span><strong>I need help now</strong><span>112, current location, siren, fake call, helplines and safety tools</span><b>Open Emergency Hub →</b>
          </button>
        </div>
        <div className="feature-grid">
          <button onClick={() => setPlanner(true)} className="feature-card"><span className="feature-number">01</span><strong>Plan a place</strong><span>Check recent reported activity around somewhere you're going tomorrow.</span><b>Safety snapshot →</b></button>
          <button onClick={() => { refreshPast(); setStep("past"); }} className="feature-card"><span className="feature-number">02</span><strong>Past reports</strong><span>See reports made from this browser without creating an account.</span><b>{past.length} stored on this device →</b></button>
          <button onClick={() => setStep("contacts")} className="feature-card"><span className="feature-number">03</span><strong>Trusted contacts</strong><span>Keep emergency contacts locally on this device for quick sharing.</span><b>{contacts.length} contact{contacts.length === 1 ? "" : "s"} →</b></button>
        </div>
        {journey && <div className="journey-strip"><div><span className="eyebrow pink">ACTIVE CHECK-IN</span><strong>Journey monitor is on</strong><span>Next check-in in {formatTimer(journeyLeft)}</span></div><button className="primary" onClick={checkIn}>I'm safe</button><button className="secondary" onClick={() => { setJourney(null); localStorage.removeItem("safeline-journey"); }}>End</button></div>}
        <div className="citizen-explainer"><div><span className="eyebrow">THE SAFELINE LOOP</span><h2>Report → integrity → review → action → monitoring</h2><p>A report is a signal, not proof. Repeated sources are capped, compatible reports become occurrences, and authorities must record what they checked before closing an action.</p></div><div className="mini-process"><span>01 Receive</span><span>02 Understand</span><span>03 Act</span><span>04 Monitor</span></div></div>
      </>}

      {step === "location" && <Step title="Choose the reporting location" onBack={() => setStep("home")}>
        <p className="muted">This is the first step while offline or when GPS is unavailable. Choose the place where the incident happened before selecting what happened.</p>
        {gpsAvailable && !selectedSpot && !manualLocation && <div className="detected-location-card">
          <div><span className="eyebrow">LOCATION</span><strong>{location.label}</strong><small>One-time location point for this report. No continuous tracking.</small></div>
          <span className="location-ready-badge">Detected</span>
        </div>}
        <div className="spot-fallback report-location-first">
          <div className="location-choice-head"><strong>{gpsAvailable ? "Change location" : online ? "Location unavailable — choose a location" : "Offline reporting location"}</strong><span>{spots.length ? `${spots.length} locations available offline` : "No cached locations yet"}</span></div>
          {spots.length > 0 && <>
            <input className="location-search" aria-label="Search location" value={spotSearch} onChange={e => { setSpotSearch(e.target.value); setErr(""); }} placeholder="Search location…" autoComplete="off" />
            <div className="location-option-list" role="listbox" aria-label="Suggested locations">
              {filteredSpots.length ? filteredSpots.map(s => <button type="button" role="option" aria-selected={spotChoice===s.id} key={s.id} className={`location-option ${spotChoice===s.id ? "selected" : ""}`} onClick={() => { setSpotChoice(s.id); setManualLocation(""); setErr(""); }}><strong>{s.name}</strong>{s.zone_name&&<small>{s.zone_name}</small>}</button>) : <div className="empty small-empty">No matching location. Enter a public place below.</div>}
            </div>
          </>}
          {selectedSpot && <div className="selected-location"><span>✓</span><div><strong>{selectedSpot.name}</strong><small>Location selected</small></div><button type="button" className="secondary" onClick={() => { setSpotChoice(""); setSpotSearch(""); }}>Change</button></div>}
          <div className="manual-location-row">
            <input value={manualLocation} onChange={e => { setManualLocation(e.target.value); setSpotChoice(""); setErr(""); }} placeholder="Or enter a public place / landmark" maxLength={180} autoComplete="off"/>
            {manualLocation && <button className="secondary" type="button" onClick={() => setManualLocation("")}>Clear</button>}
          </div>
          <small>Registered locations use known coordinates. A manual location is stored as a text label only.</small>
        </div>
        {locationReady && <div className="inline-category ready">
          <div className="section-title-row"><div><span className="eyebrow pink">NEXT · 1 TAP</span><h3>What happened?</h3><p className="muted">Choose a category below. Your report is sent immediately.</p></div><strong className="location-ready-badge">Location selected</strong></div>
          <div className="choice-grid">{categories.map(([v, l]) => <button className="choice" onClick={() => quickSubmit(v)} key={v} disabled={loading}>{l}</button>)}</div>
        </div>}
        {err && <div className="error">{err}</div>}
      </Step>}

      {step === "category" && <Step title="Tap what happened" onBack={() => setStep("home")}>
        <div className="detected-location-card category-location-card">
          <div><span className="eyebrow">LOCATION</span><strong>{gpsAvailable ? location.label : "Current location unavailable"}</strong><small>{gpsAvailable ? "Captured automatically for this report. No location selection step is needed online." : "Allow location access so SafeLine can attach the incident point."}</small></div>
          {gpsAvailable && <span className="location-ready-badge">Detected</span>}
        </div>
        <p className="muted category-helper">Choose a category. Your report is sent immediately.</p>
        <div className="choice-grid">{categories.map(([v, l]) => <button className="choice" onClick={() => quickSubmit(v)} key={v} disabled={loading}>{l}</button>)}</div>
      </Step>}

      {step === "context" && <Step title={editingReportId ? "Add context to your report" : "A little context"} onBack={() => setStep("category")}>
        <div className="section-title">Reporting as</div>
        <div className="segmented">{[["self", "It happened to me"], ["witness", "I witnessed it"]].map(([v, l]) => <button className={who === v ? "selected" : ""} onClick={() => setWho(v)} key={v}>{l}</button>)}</div>
        <div className="section-title">When?</div>
        <div className="segmented">{[["just_now", "Just now"], ["earlier_today", "Earlier today"], ["earlier", "Earlier"]].map(([v, l]) => <button className={when === v ? "selected" : ""} onClick={() => setWhen(v)} key={v}>{l}</button>)}</div>
        <div className="section-title">Still happening?</div>
        <div className="segmented">{[[false, "No / not sure"], [true, "Yes"]].map(([v, l]) => <button className={still === v ? "selected" : ""} onClick={() => setStill(v)} key={String(v)}>{l}</button>)}</div>
        {still && <div className="notice">If you are in immediate danger, use the separate Emergency Hub. A routine report does not automatically dispatch emergency services.</div>}
        <button className="primary full" onClick={editingReportId ? saveContext : () => setStep("review")}>{editingReportId ? (loading ? "Saving…" : "Add context to report") : "Review report"}</button>
      </Step>}

      {step === "review" && <Step title="Review before sending" onBack={() => setStep("context")}>
        <div className="review-card"><div><span>What</span><strong>{categories.find(x => x[0] === cat)?.[1]}</strong></div><div><span>When</span><strong>{when.replaceAll("_", " ")}</strong></div><div><span>Reporting as</span><strong>{who === "witness" ? "Witness" : "Self"}</strong></div><div><span>Location</span><strong>{selectedSpot?.name || (gpsAvailable ? location.label : manualLocation || "Not selected")}</strong></div></div>
        <textarea value={note} onChange={e => setNote(e.target.value)} placeholder="Optional short context (do not identify a person)" maxLength={240} autoComplete="off"/>
        <div className="privacy-note">Only one current/selected location point is attached. SafeLine does not build a movement history.</div>
        <button className="primary full" disabled={loading || !locationReady} onClick={submit}>{loading ? "Sending to authority workspace…" : online ? "Submit report" : "Save report offline"}</button>
        {err && <div className="error">{err}</div>}
      </Step>}

      {step === "receipt" && <div className="receipt-page"><div className="success-mark">✓</div><span className="eyebrow pink">{receipt?.offline ? "SAVED OFFLINE" : "REPORT RECEIVED"}</span><h2>{receipt?.location_label}</h2><p>{receipt?.offline ? "This report is stored on this device and will be sent automatically when the connection returns." : "Your report is now visible to the authority inbox. It will move through integrity checks, occurrence analysis, human review and action tracking."}</p>{!receipt?.offline && receipt?.assigned_authority && <div className="routing-strip"><span className="eyebrow">ROUTING</span><strong>Automatically routed to {receipt.assigned_authority}</strong><small>Nearest authority selected from the report location.</small></div>}<div className="receipt-id">{receipt?.report_id}<span>REPORT ID</span></div><div className="receipt-flow"><span>Saved</span><i>→</i><span>Integrity</span><i>→</i><span>Review</span><i>→</i><span>Action</span><i>→</i><span>Monitor</span></div><div className="undo-strip">{undoUntil ? <><strong>Sent just now</strong><span>You have {undoSeconds}s to undo this report.</span><button className="secondary" onClick={undoLastReport}>Undo report</button></> : <><strong>{receipt?.offline ? "Waiting for connection." : "Report is now in the authority workflow."}</strong><button className="secondary" onClick={addContext}>Add / update context</button></>}</div><div className="button-row"><button className="primary" onClick={() => setStep("past")}>View my reports</button><button className="secondary" onClick={() => checkStatus(receipt?.report_id)}>Check this report</button><button className="secondary" onClick={reset}>New report</button></div>{statusResult && <StatusResult result={statusResult}/>}</div>}

      {step === "status" && <Step title="Track your report" onBack={() => setStep("home")}><p className="muted">Your report ID is a fallback. Reports made from this browser also appear in Past reports.</p><input value={statusId} onChange={e => setStatusId(e.target.value)} placeholder="RPT-XXXXXXXX" autoComplete="off"/><button className="primary full" onClick={() => checkStatus()}>Check status</button>{statusResult && <StatusResult result={statusResult}/>} {err && <div className="error">{err}</div>}</Step>}

      {step === "past" && <Step title="Your past reports" onBack={() => setStep("home")}><div className="privacy-note">No account is used. This history is tied to a pseudonymous browser token stored locally on this device. Offline reports remain local until they sync.</div><div className="past-list">{past.length ? past.map(r => <button className="past-row" key={r.id} onClick={() => { setStatusId(r.id); checkStatus(r.id); }}><div><strong>{r.category_label}</strong><span>{r.location_label}</span><small>{new Date(r.received_at).toLocaleString()}</small></div><div><Status tier={r.tier}/><b>{workflowLabel(r.status)}</b></div></button>) : <div className="empty">No reports are stored on this device yet.</div>}</div>{statusResult && <StatusResult result={statusResult}/>}</Step>}

      {step === "contacts" && <Contacts contacts={contacts} save={saveContact} remove={removeContact} back={() => setStep("home")}/>}
      {step === "fakecall" && <div className="fake-call"><div className="call-avatar">M</div><span>Incoming call</span><strong>{contacts[0]?.name || "Mother"}</strong><small>Mobile</small><div className="call-actions"><button className="decline" onClick={() => setStep("home")}>Decline</button><button className="accept" onClick={() => setStep("home")}>Accept</button></div></div>}
      {step === "help" && <Step title="Emergency support" onBack={() => setStep("home")}><div className="help-box"><span className="eyebrow pink">IMMEDIATE DANGER</span><h2>Call 112 first</h2><p>SafeLine does not replace emergency services.</p><a className="emergency" href="tel:112">Call 112</a></div><div className="help-share"><div><strong>Share one current location point with the authority workspace</strong><span>No continuous tracking.</span></div><button className="primary" disabled={loading || location.lat == null || !!helpResult} onClick={requestHelp}>{helpResult ? "Location shared" : loading ? "Sharing…" : "Share location"}</button></div>{helpResult && <div className="success-panel"><span className="eyebrow pink">REQUEST RECORDED</span><h3>Authority workspace received the location</h3><strong>{helpResult.request_id}</strong><p>{location.label}</p></div>}{err && <div className="error">{err}</div>}</Step>}

    </main>
    <div className="floating-dock"><button className="dock-report" aria-label="Report an unsafe incident" onClick={startReport}><span>REPORT</span><b>＋</b></button><button className="dock-sos" aria-label="Open emergency safety tools" onClick={() => setHub(true)}><span>SOS</span><b>!</b></button></div>
    {hub && <EmergencyHub onClose={() => setHub(false)} call112={() => window.location.href = "tel:112"} share={requestHelp} shareMessage={shareSafetyMessage} fakeCall={fakeCall} siren={toggleSiren} sirenOn={sirenOn} contacts={contacts} location={location} startJourney={startJourney}/>}
    {planner && <Planner location={location} onClose={() => setPlanner(false)}/>}
  </Shell>;
}

function Step({title,children,onBack}){return <section className="step"><button className="back" onClick={onBack}>← Back</button><span className="eyebrow pink">QUICK REPORT</span><h2>{title}</h2>{children}</section>}
function Status({tier}){return <span className={`status-badge ${String(tier||"WATCH").toLowerCase().replaceAll(" ","-")}`}>{tier||"WATCH"}</span>}
function workflowLabel(status){return ({received:"Received",acknowledged:"Acknowledged by authority",under_review:"Under review",action_in_progress:"Action in progress",completed:"Completed",monitoring:"Monitoring",reopened:"Reopened"}[status]||String(status||"").replaceAll("_"," "));}
function StatusResult({result}){const labels={received:"Received",acknowledged:"Acknowledged by authority",under_review:"Under review",action_in_progress:"Action in progress",completed:"Completed",monitoring:"Monitoring",reopened:"Reopened"};return <div className="status-result"><div><span>Location</span><strong>{result.location_label}</strong></div><div><span>Assigned authority</span><strong>{result.assigned_authority||authorityFallback}</strong></div><div><span>Signal</span><Status tier={result.tier}/></div><div><span>Authority workflow</span><strong className="workflow-label">{labels[result.status]||result.status.replaceAll("_"," ")}</strong></div><div><span>Latest action</span><strong>{result.action_type||"Awaiting next authority step"}</strong></div></div>}
function Contacts({contacts,save,remove,back}){const [name,setName]=useState("");const[phone,setPhone]=useState("");return <section className="step"><button className="back" onClick={back}>← Back</button><span className="eyebrow pink">SAFETY TOOLS</span><h2>Trusted contacts</h2><p className="muted">Contacts stay in this browser for the demo. SafeLine does not upload them as part of an ordinary report.</p><div className="contact-form"><input value={name} onChange={e=>setName(e.target.value)} placeholder="Name"/><input value={phone} onChange={e=>setPhone(e.target.value)} placeholder="Phone"/><button className="primary" onClick={()=>{save(name,phone);setName("");setPhone("")}}>Add contact</button></div><div className="contact-list">{contacts.map(c=><div className="contact-row" key={c.id}><div><strong>{c.name}</strong><span>{c.phone}</span></div><button onClick={()=>remove(c.id)}>Remove</button></div>)}{!contacts.length&&<div className="empty">No trusted contacts saved yet.</div>}</div></section>}

function EmergencyHub({onClose,call112,share,shareMessage,fakeCall,siren,sirenOn,contacts,location,startJourney}){return <div className="modal-backdrop"><div className="emergency-hub"><div className="hub-head"><div><span className="eyebrow pink">QUICK SAFETY TOOLS</span><h2>Emergency Hub</h2><p>One place for urgent tools. SafeLine notifies the authority workspace; trusted-contact alerts open your device's SMS composer.</p></div><button className="close" aria-label="Close" onClick={onClose}>×</button></div><div className="hub-grid"><button className="hub-tile danger" onClick={call112}><strong>Call 112</strong><span>Emergency services</span></button><button className="hub-tile" onClick={share}><strong>Share current location</strong><span>Authority + trusted contact · one current point</span></button><button className={`hub-tile ${sirenOn?"active":""}`} onClick={siren}><strong>{sirenOn?"Siren on":"Emergency siren"}</strong><span>Local sound alert</span></button><button className="hub-tile" onClick={fakeCall}><strong>Fake call from {contacts[0]?.name||"Mother"}</strong><span>Simulated incoming call</span></button><button className="hub-tile" onClick={()=>window.location.href="tel:181"}><strong>Women Helpline 181</strong><span>Government support line</span></button><button className="hub-tile" onClick={shareMessage}><strong>Send safety message</strong><span>Authority + trusted contact</span></button><button className="hub-tile" onClick={()=>startJourney(15)}><strong>15-min check-in</strong><span>Dead-man's-switch style safety timer</span></button></div><div className="hub-contacts"><span className="eyebrow">TRUSTED CONTACTS</span>{contacts.length?contacts.map(c=><a key={c.id} href={`tel:${c.phone}`}><strong>{c.name}</strong><span>{c.phone}</span></a>):<p>No contacts saved. Add one so emergency alerts can be addressed to someone you trust.</p>}</div><div className="hub-footer">A browser cannot silently send an SMS without the device messaging app's permission. SafeLine sends the location to its authority dashboard immediately and opens a pre-addressed SMS for the first trusted contact.</div></div></div>}
function Planner({location,onClose}){const [query,setQuery]=useState("");const[place,setPlace]=useState(null);const[data,setData]=useState(null);const[loading,setLoading]=useState(false);const[err,setErr]=useState("");const search=async()=>{if(!query.trim())return;setLoading(true);setErr("");try{const r=await fetch(`https://nominatim.openstreetmap.org/search?format=jsonv2&limit=1&q=${encodeURIComponent(query)}`,{headers:{Accept:"application/json"}});const d=await r.json();if(!d[0])throw new Error("Place not found");const p={lat:Number(d[0].lat),lng:Number(d[0].lon),label:d[0].display_name};setPlace(p);setData(await api("/api/planning/overview",{method:"POST",body:JSON.stringify({latitude:p.lat,longitude:p.lng,radius_km:1.5})}));}catch(e){setErr(e.message)}finally{setLoading(false)}};const useCurrent=async()=>{if(location.lat==null)return;setPlace({lat:location.lat,lng:location.lng,label:location.label});setLoading(true);try{setData(await api("/api/planning/overview",{method:"POST",body:JSON.stringify({latitude:location.lat,longitude:location.lng,radius_km:1.5})}))}catch(e){setErr(e.message)}finally{setLoading(false)}};return <div className="modal-backdrop"><div className="planner"><div className="hub-head"><div><span className="eyebrow pink">PLANNING MODE</span><h2>Before you go</h2><p>Use reported activity as context, not as a guarantee of safety.</p></div><button className="close" aria-label="Close" onClick={onClose}>×</button></div><div className="planner-search"><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search a place for tomorrow…"/><button className="primary" onClick={search}>{loading?"Checking…":"Check area"}</button><button className="secondary" onClick={useCurrent}>Use current location</button></div>{err&&<div className="error">{err}</div>}{place&&<div className="place-card"><span className="eyebrow">AREA SNAPSHOT</span><strong>{place.label}</strong>{data&&<><div className="snapshot-signal"><span>{data.signal}</span><b>{data.reports_30d} reports · {data.distinct_sources_30d} reporting sources · last 30 days</b></div>{data.is_demo_data&&<div className="demo-data-banner">DEMO BASELINE · No local SafeLine reports found here, so this snapshot uses clearly labelled synthetic demo activity.</div>}<p>{data.explanation}</p><div className="category-bars">{Object.entries(data.categories).map(([k,v])=><div key={k}><span>{k}</span><i><b style={{width:`${Math.min(100,v*18)}%`}}></b></i><strong>{v}</strong></div>)}</div>{data.active_concerns.length>0&&<div className="planner-alert"><strong>Active pattern concerns nearby</strong>{data.active_concerns.map((a,i)=><span key={i}>{a.tier} · {a.location_label} · {a.distance_m}m away</span>)}</div>}</>}</div>}{!place&&<div className="planner-empty"><strong>What you'll see</strong><span>30-day reported activity, distinct sources, categories and any active pattern concern within 1.5 km.</span></div>}</div></div>}

function Authority({go}){const [session,setSession]=useState(()=>JSON.parse(localStorage.getItem("safeline-authority")||"null"));const [theme,toggleTheme]=useTheme();if(!session)return <AuthorityLogin onLogin={s=>{localStorage.setItem("safeline-authority",JSON.stringify(s));setSession(s)}} go={go}/>;return <AuthorityWorkspace session={session} onLogout={()=>{localStorage.removeItem("safeline-authority");setSession(null)}} go={go}/>}
function AuthorityLogin({onLogin,go}){const[id,setId]=useState(demoPolice);const[pin,setPin]=useState("1234");const[err,setErr]=useState("");const submit=async()=>{try{setErr("");onLogin(await api("/api/authority/login",{method:"POST",body:JSON.stringify({police_id:id,pin})}))}catch(e){setErr(e.message)}};return <div className="login-page"><div className="login-card"><div className="login-brand"><span className="brand-mark">S</span><strong>SafeLine</strong></div><span className="eyebrow pink">AUTHORITY ACCESS</span><h1>Safety Operations Center</h1><p>Demo access is restricted to the authority workspace. Citizen reporting remains account-free.</p><input value={id} onChange={e=>setId(e.target.value)} placeholder="Police ID"/><input value={pin} onChange={e=>setPin(e.target.value)} placeholder="Demo PIN" type="password"/><button className="primary full" onClick={submit}>Sign in</button>{err&&<div className="error">{err}</div>}<button className="mode-link login-citizen" onClick={()=>go("/")}>← Back to citizen view</button></div></div>}

function AuthorityWorkspace({session,onLogout,go}) {
  const [data,setData]=useState({concerns:[],counts:{},recent_reports:[]});
  const [tab,setTab]=useState("concerns");
  const [caseStep,setCaseStep]=useState("overview");
  const [selected,setSelected]=useState(null);
  const [detail,setDetail]=useState(null);
  const [assistance,setAssistance]=useState([]);
  const [map,setMap]=useState({reports:[],spots:[],branches:[],assistance:[]});
  const [toast,flashToast,clearToast]=useTransientError();
  const [err,showError,clearError]=useTransientError();
  const [lastCount,setLastCount]=useState(null);
  const [sidebarOpen,setSidebarOpen]=useState(true);
  const [settings,setSettings]=useState(()=>JSON.parse(localStorage.getItem("safeline-authority-settings")||'{"autoRefresh":true,"compact":false}'));
  const detailRequestRef=useRef(0);

  const flash=(message,duration=3500)=>{flashToast(message,duration)};
  const load=async()=>{
    try{
      const [d,h]=await Promise.all([authApi("/api/authority/summary",session.token),authApi("/api/authority/assistance",session.token)]);
      if(lastCount!==null && d.counts.reports>lastCount) flash("New citizen report received",4000);
      setLastCount(d.counts.reports); setData(d); setAssistance(h.requests||[]);
    }catch(e){ if(e.message.toLowerCase().includes("session"))onLogout(); else showError(e); }
  };
  const reloadDetail=async(alertId=selected?.alert_id)=>{
    if(!alertId)return null;
    const requestId=++detailRequestRef.current;
    try{
      const fresh=await authApi(`/api/authority/concerns/${alertId}`,session.token);
      // A slower request for case A must never overwrite the already selected case B.
      if(requestId!==detailRequestRef.current)return null;
      setDetail(fresh);
      return fresh;
    }catch(e){
      if(requestId===detailRequestRef.current)showError(e);
      return null;
    }
  };
  useEffect(()=>{load();if(!settings.autoRefresh)return;const t=setInterval(load,4000);return()=>clearInterval(t)},[settings.autoRefresh]);
  useEffect(()=>{if(selected?.alert_id)reloadDetail(selected.alert_id);else setDetail(null)},[selected?.alert_id]);
  useEffect(()=>{if(tab==="map")authApi("/api/authority/map",session.token).then(setMap).catch(showError)},[tab,data.counts.reports]);

  const openConcern=async(c,step="overview")=>{
    if(!c?.alert_id)return;
    // Invalidate any in-flight request for the previously selected case before
    // changing the UI context. This also prevents old evidence from flashing in.
    ++detailRequestRef.current;
    setDetail(null);
    setSelected(c);
    setCaseStep(step);
    setTab("concerns");
    await reloadDetail(c.alert_id);
  };
  const goCaseStep=step=>{if(selected?.alert_id){setCaseStep(step);setTab("concerns")}else showError("Select a case first.")};
  const update=async(status,action_type,observation)=>{
    if(!selected?.alert_id)return;
    try{
      await authApi(`/api/authority/concerns/${selected.alert_id}/status`,session.token,{method:"POST",body:JSON.stringify({status,action_type:action_type||detail?.action_type||null,observation:observation||detail?.observation||null})});
      const labels={acknowledged:"Case acknowledged",reviewing:"Signal review started",action_planned:"Action recorded",action_due:"Action marked due",completed:"Case completed",monitoring:"Monitoring started",reopened:"Case reopened"};
      flash(labels[status]||"Case updated");
      await load(); await reloadDetail(selected.alert_id);
    }catch(e){showError(e)}
  };
  const ack=id=>authApi(`/api/authority/reports/${id}/acknowledge`,session.token,{method:"POST"}).then(()=>{flash("Report acknowledged");load()}).catch(showError);
  const ackHelp=id=>authApi(`/api/authority/assistance/${id}/acknowledge`,session.token,{method:"POST"}).then(()=>{flash("Assistance request acknowledged");load()}).catch(showError);
  const integrity=async(id,classification,note)=>{try{await authApi(`/api/authority/reports/${id}/integrity`,session.token,{method:"POST",body:{classification,note:note||null}});flash("Integrity review recorded");await load();if(selected?.alert_id)await reloadDetail(selected.alert_id);return true}catch(e){showError(e);return false}};
  const updateSetting=(key,value)=>{const next={...settings,[key]:value};setSettings(next);localStorage.setItem("safeline-authority-settings",JSON.stringify(next))};

  const stepItems=[
    ["reports","01","Reports","Review incoming signals"],
    ["concerns","02","Cases","Open a case"],
    ["signal","03","Signal review","Understand the pattern"],
    ["verify","04","Human verification","Record site observation"],
    ["action","05","Preventive action","Choose response"],
    ["evidence","06","Action record","Upload completion record"],
    ["supervisor","07","Supervisor approval","Approve completion"],
    ["monitoring","08","Monitoring","Continue after action"],
  ];
  const activeAuthority = data.recent_reports?.find(r => r.assigned_authority)?.assigned_authority || session.station || authorityFallback;
  const utilityItems=[
    ["map","Map","Reported locations"],
    ["integrity","Signal integrity","Isolated Attack Lab"],
    ["settings","Settings","Station configuration"],
  ];
  const stepActive=(id)=>id==="reports"?tab==="inbox":id==="concerns"?tab==="concerns"&&caseStep==="overview":tab==="concerns"&&caseStep===id;
  return <Shell mode="Authority" onSwitch={()=>go("/")}>
    <main className={`authority authority-shell ${sidebarOpen?"sidebar-open":"sidebar-closed"}`}>
      <div className="authority-layout">
        <aside className="authority-sidebar">
          <div className="sidebar-brand-row">
            <button className="brand sidebar-brand" onClick={()=>{setTab("concerns");setCaseStep("overview")}} aria-label="SafeLine home">
              <span className="brand-mark">S</span>{sidebarOpen&&<span><strong>SafeLine</strong><small>Safety operations</small></span>}
            </button>
            <button className="sidebar-toggle" onClick={()=>setSidebarOpen(v=>!v)} aria-label={sidebarOpen?"Collapse sidebar":"Expand sidebar"}>{sidebarOpen?"‹":"›"}</button>
          </div>
          {sidebarOpen&&<div className="sidebar-context"><span className="sidebar-kicker">CASE WORKFLOW</span><strong>One step at a time.</strong></div>}
          <nav className="sidebar-nav authority-main-nav">
            {stepItems.map(([id,num,label,sub])=><button key={id} className={stepActive(id)?"active":""} onClick={()=>id==="reports"?setTab("inbox"):goCaseStep(id)} title={label}>
              <b>{num}</b>{sidebarOpen&&<span><strong>{label}</strong><small>{id==="reports"?(data.counts.new_reports||0)+" new":selected?sub:"Select a case"}</small></span>}
            </button>)}
          </nav>
          <div className="sidebar-divider"/>
          <nav className="sidebar-nav utility-nav">
            {utilityItems.map(([id,label,sub])=><button key={id} className={tab===id?"active":""} onClick={()=>setTab(id)} title={label}><span>{id==="map"?"M":id==="integrity"?"S":"C"}</span>{sidebarOpen&&<span><strong>{label}</strong><small>{sub}</small></span>}</button>)}
          </nav>
          <button className="citizen-return" onClick={()=>go("/")} title="Citizen view"><span>←</span>{sidebarOpen&&<span>Citizen view</span>}</button>
        </aside>
        <section className="authority-content">
          <div className="authority-page-head">
            <div><span className="eyebrow pink">SAFELINE · {activeAuthority.toUpperCase()}</span><h1>{tab==="inbox"?"Reports":tab==="concerns"?(caseStep==="overview"?"Emerging concerns":stepItems.find(x=>x[0]===caseStep)?.[2]||"Case"):tab==="map"?"Location intelligence":tab==="integrity"?"Signal integrity":"Station settings"}</h1><p>{tab==="concerns"&&detail?`${detail.location_label} · Case ${detail.id}`:activeAuthority}</p></div>
            <div className="authority-head-right">
              <div className="officer-card compact-officer"><span className="live-dot"></span><div><strong>{session.name}</strong><span>{session.role} · {session.station}</span></div></div>
            </div>
          </div>
          {tab==="inbox"&&<ReportInbox reports={data.recent_reports} openConcern={(c)=>openConcern(c,"overview")} acknowledge={ack} integrity={integrity} session={session}/>} 
          {tab==="concerns"&&<ConcernWorkspace data={data} detail={detail} selected={selected} openConcern={openConcern} update={update} session={session} caseStep={caseStep} setCaseStep={goCaseStep} reloadDetail={reloadDetail}/>} 
          {tab==="map"&&<MapView map={map} assistance={assistance} acknowledgeHelp={ackHelp}/>} 
          {tab==="integrity"&&<Integrity session={session}/>} 
          {tab==="settings"&&<AuthoritySettings session={session} settings={settings} updateSetting={updateSetting} onLogout={onLogout}/>} 
          {toast&&<div className="toast success-toast">✓ {toast}</div>}{err&&<div className="global-error">{err}<button onClick={clearError}>×</button></div>}
        </section>
      </div>
    </main>
  </Shell>;
}

function ConcernWorkspace({data,detail,selected,openConcern,update,session,caseStep,setCaseStep,reloadDetail}){
  if(caseStep==="overview") { const concerns=[...(data.concerns||[])].sort((a,b)=>new Date(b.last_report_at||0)-new Date(a.last_report_at||0)); return <div className="case-page"><div className="case-list-panel"><div className="case-overview-banner"><div><span className="eyebrow">EMERGING CONCERNS</span><h2>Open cases</h2></div><span className="muted">{concerns.length} open</span></div><div className="case-empty compact-empty"><span className="eyebrow">CASE</span><strong>Select a case to begin review</strong><span>Cases are ordered by most recent report.</span></div><div className="queue">{concerns.map(c=><button className={`queue-card ${selected?.alert_id===c.alert_id?"selected":""}`} key={c.alert_id} onClick={()=>openConcern(c,"overview")}><div><Status tier={c.tier}/><span>{c.status.replaceAll("_"," ")}</span><time>{c.last_report_at?timeAgo(c.last_report_at):""}</time></div><h3>{c.spot_name}</h3><p>{c.report_count} reports · {c.distinct_reporters} sources · {c.occurrence_count} occurrences</p><small>{c.why?.slice(0,2).join(" · ")}</small></button>)}{!concerns.length&&<div className="empty">No reviewable concerns right now.</div>}</div></div></div>; }
  if(!detail) return <div className="case-empty"><h2>Select a case first</h2><p>Choose an emerging concern before opening a workflow step.</p></div>;
  return <ConcernDetail key={detail.id} detail={detail} update={update} session={session} step={caseStep} setStep={setCaseStep} reloadDetail={reloadDetail}/>;
}

function ConcernDetail({detail,update,session,step,setStep,reloadDetail}){
  const [obs,setObs]=useState(detail.observation||"");
  const [actionNote,setActionNote]=useState(detail.action_note||"");
  const [action,setAction]=useState(detail.action_type||"Site inspection");
  const [verification,setVerification]=useState(detail.verification?.outcome||"");
  const [evidence,setEvidence]=useState(detail.evidence||[]);
  const [file,setFile]=useState(null);
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const [error,setError]=useState("");
  useEffect(()=>{
    // Reset local form state whenever the case changes. Only values saved for this
    // case are restored; unsaved selections from another case cannot leak across.
    setObs(detail.observation||"");
    setActionNote(detail.action_note||"");
    setAction(detail.action_type||"Site inspection");
    setVerification(detail.verification?.outcome||"");
    setEvidence(Array.isArray(detail.evidence) ? detail.evidence.filter(e => e && e.alert_id === detail.id) : []);
    setFile(null);
    setMessage("");
    setError("");
  },[detail.id,detail.updated_at,detail.action_type,detail.observation,detail.verification?.outcome,detail.verification?.reviewed_at]);
  const refresh=async()=>{const fresh=await reloadDetail?.(detail.id);if(fresh){setEvidence(Array.isArray(fresh.evidence) ? fresh.evidence.filter(e => e && e.alert_id === detail.id) : []);setVerification(fresh.verification?.outcome||"");setObs(fresh.observation||"");setActionNote(fresh.action_note||"");setAction(fresh.action_type||"Site inspection")}return fresh};
  const run=async(fn,success)=>{setBusy(true);setError("");setMessage("");try{await fn();setMessage(success);await refresh()}catch(e){setError(e.message)}finally{setBusy(false)}};
  const saveVerification=()=>run(async()=>{if(!verification)throw new Error("Select a verification outcome.");if(!obs.trim())throw new Error("Add the observation before saving.");await authApi(`/api/authority/concerns/${detail.id}/verification`,session.token,{method:"POST",body:JSON.stringify({outcome:verification,note:obs.trim()})});await update("reviewing",action,obs.trim())},"Verification saved");
  const saveAction=()=>run(async()=>{if(!action)throw new Error("Select an action.");if(!actionNote.trim())throw new Error("Add an action note before recording the action.");await update("action_planned",action,actionNote.trim())},"Preventive action recorded");
  const upload=()=>run(async()=>{if(!file)throw new Error("Choose an evidence file first.");const fd=new FormData();fd.append("file",file);fd.append("action_type",action);await authApi(`/api/authority/concerns/${detail.id}/evidence`,session.token,{method:"POST",body:fd});setFile(null)},"Evidence received");
  const approve=async(id)=>run(async()=>{const target=evidence.find(e=>e.id===id);if(!target)throw new Error("Evidence record not found.");if(session.role!=="Station Supervisor")throw new Error("Station Supervisor approval required.");if(target.uploaded_by&&target.uploaded_by===session.police_id)throw new Error("A different authority user must approve the evidence.");await authApi(`/api/authority/evidence/${id}/approve`,session.token,{method:"POST",body:{approved:true,note:"Supervisor reviewed the completion record."}})},"Supervisor approval recorded");
  const openEvidence=async(id)=>{
    const popup=window.open("about:blank", "_blank");
    if(!popup){setError("Your browser blocked the evidence window. Allow pop-ups for SafeLine and try again.");return;}
    try{
      popup.document.title="SafeLine evidence";
      popup.document.body.innerHTML="<div style=\"padding:24px;font-family:system-ui\">Loading evidence…</div>";
      const response=await fetch(`${API_BASE}/api/authority/evidence/${encodeURIComponent(id)}/file`,{headers:{Authorization:`Bearer ${session.token}`}});
      if(!response.ok){
        const body=await response.json().catch(()=>({}));
        throw new Error(formatApiError(body.detail,`Could not open evidence (${response.status})`));
      }
      const blob=await response.blob();
      const mime=(response.headers.get("content-type")||blob.type||"application/octet-stream").split(";")[0].trim().toLowerCase();
      const url=URL.createObjectURL(blob);
      const filename=(response.headers.get("content-disposition")||"SafeLine evidence").replace(/^.*filename=\s*[\"]?([^\"]+)[\"]?.*$/i,"$1");
      if(mime==="application/pdf"){
        // Navigate the popup to the blob so Chrome/Edge uses its native PDF viewer.
        popup.location.href=url;
      }else if(mime.startsWith("image/")||mime.startsWith("text/")){
        popup.document.open();
        popup.document.write(`<!doctype html><html><head><title>${filename}</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;background:#f5f5f5"><iframe src="${url}" title="Evidence" style="width:100vw;height:100vh;border:0;background:white"></iframe></body></html>`);
        popup.document.close();
      }else{
        popup.document.open();
        popup.document.write(`<!doctype html><html><head><title>${filename}</title></head><body style="font-family:system-ui;padding:32px"><h2>Evidence file ready</h2><p>This file type cannot be previewed directly in the browser.</p><a href="${url}" download style="display:inline-block;padding:12px 16px;border-radius:10px;background:#d82f6c;color:#fff;text-decoration:none">Open / download evidence</a></body></html>`);
        popup.document.close();
      }
      setTimeout(()=>URL.revokeObjectURL(url),10*60*1000);
    }catch(e){
      popup.close();
      setError(e.message);
    }
  };
  const approved=evidence.some(e=>e.supervisor_approved);
  const canComplete=Boolean(verification&&obs.trim()&&evidence.length&&approved);
  const stepHeader={overview:["Emerging concern","Review the signal that reached the authority."],signal:["Signal review","Review the processed pattern before making a human decision."],verify:["Human verification","Record what was observed at the location."],action:["Take action","Record the preventive response selected by the authority."],evidence:["Action evidence","Submit the record of the action taken."],supervisor:["Supervisor approval","A separate supervisor validates the completion evidence."],monitoring:["Monitoring","Keep the location under observation after the action."],};
  const [title,subtitle]=stepHeader[step]||stepHeader.overview;
  const StepNav=()=> <div className="case-step-nav"><button onClick={()=>setStep("overview")} className={step==="overview"?"active":""}>02 <span>Case</span></button><button onClick={()=>setStep("signal")} className={step==="signal"?"active":""}>03 <span>Signal</span></button><button onClick={()=>setStep("verify")} className={step==="verify"?"active":""}>04 <span>Verify</span></button><button onClick={()=>setStep("action")} className={step==="action"?"active":""}>05 <span>Action</span></button><button onClick={()=>setStep("evidence")} className={step==="evidence"?"active":""}>06 <span>Evidence</span></button><button onClick={()=>setStep("supervisor")} className={step==="supervisor"?"active":""}>07 <span>Supervisor</span></button><button onClick={()=>setStep("monitoring")} className={step==="monitoring"?"active":""}>08 <span>Monitor</span></button></div>;
  const Notice=()=> <>{message&&<div className="action-confirmation">✓ {message}</div>}{error&&<div className="action-error">{error}</div>}</>;
  return <section className="case-page-single"><div className="case-header"><div><span className="eyebrow pink">CASE {detail.id}</span><h2>{title}</h2><p>{detail.location_label} · <Status tier={detail.tier}/> · {detail.status.replaceAll("_"," ")}</p></div><button className="secondary" onClick={()=>setStep("overview")}>Back to case</button></div><StepNav/><div className="case-window">
    {step==="overview"&&<><div className="case-summary-grid"><div><span className="eyebrow">INCIDENT LOCATION</span><strong>{detail.location_label}</strong><small>{detail.zone_name||"Registered area"} · {detail.location_source||"stored coordinates"}</small></div><div><span className="eyebrow">SIGNAL</span><strong>{detail.tier}</strong><small>{detail.report_count} reports · {detail.distinct_reporters} sources · {detail.occurrence_count} occurrences</small></div><div><span className="eyebrow">STATUS</span><strong>{detail.status.replaceAll("_"," ")}</strong><small>{detail.assigned_to||"Unassigned"}</small></div></div><div className="incident-coordinates-card"><div><span className="eyebrow">STORED INCIDENT COORDINATES</span><strong>{detail.incident_latitude!=null&&detail.incident_longitude!=null?`${Number(detail.incident_latitude).toFixed(5)}, ${Number(detail.incident_longitude).toFixed(5)}`:"Not available"}</strong><small>Used for this case and pattern analysis. No authority-device location is collected.</small></div>{detail.incident_latitude!=null&&detail.incident_longitude!=null&&<a className="secondary map-link" target="_blank" rel="noreferrer" href={`https://www.openstreetmap.org/?mlat=${detail.incident_latitude}&mlon=${detail.incident_longitude}#map=18/${detail.incident_latitude}/${detail.incident_longitude}`}>Open map</a>}</div><div className="case-actions-row"><button className="primary" disabled={detail.status!=="surfaced"} onClick={()=>update("acknowledged")}>{detail.status!=="surfaced"?"Acknowledged ✓":"Acknowledge case"}</button><button className="secondary" onClick={()=>setStep("signal")}>Open signal review →</button></div></>}
    {step==="signal"&&<><div className="processing-panel clean-processing"><div className="subhead"><div><span className="eyebrow pink">SIGNAL PROCESSING</span><h3>How this concern was formed</h3></div><Status tier={detail.tier}/></div><div className="processing-steps"><div><b>01</b><strong>Reports</strong><small>{detail.report_count} recorded</small></div><i>→</i><div><b>02</b><strong>Integrity</strong><small>{detail.distinct_reporters} sources</small></div><i>→</i><div><b>03</b><strong>Occurrences</strong><small>{detail.occurrence_count} grouped</small></div><i>→</i><div><b>04</b><strong>Baseline</strong><small>{detail.baseline?.maturity||"Calculated"}</small></div><i>→</i><div><b>05</b><strong>Trend</strong><small>{detail.trend||"Evaluated"}</small></div><i>→</i><div className="decision"><b>06</b><strong>{detail.tier}</strong><small>Decision</small></div></div></div><div className="evidence-grid"><div className="explain-card"><h3>Why this surfaced</h3>{(detail.why||[]).map(x=><div key={x}>• {x}</div>)}</div><div className="explain-card"><h3>What held it back</h3>{(detail.held_back||[]).map(x=><div key={x}>• {x}</div>)}</div></div><div className="case-actions-row"><button className="primary" onClick={()=>setStep("verify")}>Continue to verification →</button></div></>}
    {step==="verify"&&<><div className="form-window"><label>Verification outcome<select value={verification} onChange={e=>setVerification(e.target.value)}><option value="">Select outcome</option><option value="pattern_confirmed">Pattern confirmed</option><option value="pattern_not_confirmed">Pattern not confirmed</option><option value="insufficient_evidence">Insufficient evidence</option><option value="context_explains">Context explains activity</option><option value="reporting_integrity_concern">Reporting integrity concern</option></select></label><label>Observation<textarea value={obs} onChange={e=>setObs(e.target.value)} placeholder="What was checked and what was observed?"/></label><Notice/><div className="case-actions-row"><button className="primary" disabled={busy||!verification||!obs.trim()} onClick={saveVerification}>{busy?"Saving…":detail.verification?.outcome?"Verification saved ✓":"Save verification"}</button><button className="secondary" disabled={!detail.verification?.outcome} onClick={()=>setStep("action")}>Next: Take action →</button></div></div></>}
    {step==="action"&&<><div className="form-window"><label>Preventive action<select value={action} onChange={e=>setAction(e.target.value)}><option>Site inspection</option><option>Lighting inspection</option><option>Increased patrol presence</option><option>CCTV review</option><option>Local coordination</option></select></label><label>Action note<textarea value={actionNote} onChange={e=>setActionNote(e.target.value)} placeholder="Record what will be checked, changed or coordinated."/></label><Notice/><div className="case-actions-row"><button className="primary" disabled={busy||!actionNote.trim()} onClick={saveAction}>{busy?"Saving…":detail.action_type?"Action recorded ✓":"Record action"}</button><button className="secondary" disabled={!detail.action_type} onClick={()=>setStep("evidence")}>Next: Evidence →</button></div></div></>}
    {step==="evidence"&&<><div className="form-window"><div className="case-evidence-context"><span className="eyebrow">CASE-SCOPED EVIDENCE</span><strong>{detail.id}</strong><small>Only evidence uploaded for this case appears below. Evidence from another case is never reused here.</small></div><div className="upload-row large-upload"><input type="file" accept=".pdf,.doc,.docx,.txt,.jpg,.jpeg,.png" onChange={e=>setFile(e.target.files?.[0]||null)}/><button className="primary" disabled={busy||!file} onClick={upload}>{busy?"Uploading…":file?"Upload evidence":"Choose evidence"}</button></div><Notice/><div className="evidence-list">{evidence.map(e=><div className="evidence-file enhanced-evidence" key={e.id}><div className="evidence-main"><strong>{e.filename}</strong><span className="evidence-meta">{String(e.precheck_status||"uploaded").replaceAll("_"," ")} · {e.action_type||action} · {e.uploaded_by||"unknown uploader"}</span><span className="evidence-meta">SHA-256 {String(e.sha256||"").slice(0,16)}… · {e.uploaded_at?new Date(e.uploaded_at).toLocaleString():"received"}</span><details><summary>Evidence analysis</summary><div className="evidence-analysis"><p>{e.precheck_summary||"Received for human review."}</p><div className="evidence-relevance-label">{e.ai_analysis?.relevance_label||"Human review required"}</div>{e.ai_analysis?.components?<div className="analysis-components">{Object.entries(e.ai_analysis.components).map(([k,v])=><div key={k}><span>{k.replaceAll("_"," ")}</span><strong>{v}</strong></div>)}</div>:null}{e.ai_analysis?.flags?.length?<div className="analysis-flags">{e.ai_analysis.flags.map(f=><span key={f}>Attention: {f.replaceAll("_"," ")}</span>)}</div>:null}<small>Consistency/relevance assistance only. It does not independently verify that an action occurred or prove document authenticity.</small></div></details></div><b className={e.supervisor_approved?"verified":"pending-badge"}>{e.supervisor_approved?"APPROVED":"AWAITING APPROVAL"}</b></div>)}{!evidence.length&&<div className="empty">No completion evidence has been uploaded.</div>}</div><div className="case-actions-row"><button className="secondary" onClick={()=>setStep("supervisor")}>Next: Supervisor →</button></div></div></>}
    {step==="supervisor"&&<><div className="form-window"><div className="supervisor-state"><span className={approved?"state-icon done":"state-icon"}>{approved?"✓":""}</span><div><strong>{approved?"Completion evidence approved":"Supervisor approval required"}</strong><small>{approved?"A separate authority user has approved the evidence.":session.role==="Station Supervisor"?"Review the evidence below and approve it when satisfied.":"This step must be completed by a Station Supervisor."}</small></div></div><div className="evidence-list">{evidence.map(e=><div className="evidence-file" key={e.id}><div><strong>{e.filename}</strong><span>{e.precheck_summary||"Evidence record received."}</span><span className="evidence-meta">Uploaded by {e.uploaded_by||"unknown"} · {e.uploaded_at?new Date(e.uploaded_at).toLocaleString():"received"}</span></div><div className="evidence-actions"><button className="secondary small-action" disabled={busy} onClick={()=>openEvidence(e.id)}>Open evidence</button>{e.supervisor_approved?<b className="verified">SUPERVISOR APPROVED</b>:session.role!=="Station Supervisor"?<span className="muted">Awaiting supervisor</span>:e.uploaded_by===session.police_id?<span className="muted approval-blocked">Uploaded by you · another supervisor required</span>:<button className="primary small-action" disabled={busy} onClick={()=>approve(e.id)}>{busy?"Saving…":"Approve evidence"}</button>}</div></div>)}</div><div className="case-actions-row"><button className="primary" disabled={!canComplete||busy} onClick={()=>update("completed",action,obs)}>{canComplete?"Complete case":"Complete case — approval required"}</button><button className="secondary" disabled={!approved} onClick={()=>setStep("monitoring")}>{approved?"Go to monitoring →":"Monitoring unlocks after approval"}</button></div><Notice/></div></>}
    {step==="monitoring"&&<><div className="monitor-window"><div><span className="eyebrow">POST-ACTION STATUS</span><h3>{detail.status==="monitoring"?"Monitoring active":detail.status==="completed"?"Completion recorded — monitoring not started":"Monitoring is locked"}</h3><p>{detail.status==="monitoring"?"New reports continue to be processed for this location.":detail.status==="completed"?"The supervisor-approved action is complete. Monitoring is now the next operational state.":"Monitoring cannot start until human verification, preventive action, evidence and supervisor approval are complete."}</p></div><div className="monitor-status"><span>Current case status</span><strong>{detail.status.replaceAll("_"," ")}</strong></div></div><Notice/><div className="case-actions-row"><button className="primary" disabled={busy||detail.status!=="completed"} onClick={()=>update("monitoring",action,obs)}>{detail.status==="monitoring"?"Monitoring active ✓":detail.status==="completed"?"Start monitoring":"Awaiting supervisor approval"}</button><button className="secondary" onClick={()=>setStep("overview")}>Return to case</button></div></>}
  </div></section>;
}

function ReportInbox({reports,openConcern,acknowledge,integrity,session}){const [selectedReport,setSelectedReport]=useState(null);return <section className="workspace-card inbox-page"><div className="panel-head"><div><span className="eyebrow">AUTHORITY INBOX</span><h2>Every report, accounted for</h2><p>Review the exact submission before it influences a pattern decision.</p></div><span className="inbox-live">AUTO-REFRESH</span></div><div className="inbox-table"><div className="table-head"><span>Signal</span><span>Location</span><span>Received</span><span>Pattern</span><span>Authority</span><span></span></div>{reports.map(r=><div className={`table-row ${r.authority_status==="new"?"unread":""}`} key={r.id}><div><strong>{r.category_label}</strong><small>{r.id}</small></div><div><strong>{r.location_label}</strong><small>{r.assigned_authority || authorityFallback} · {r.location_source === "gps" ? "Location point attached" : "Registered reporting spot"}</small></div><span>{timeAgo(r.received_at)}</span><Status tier={r.tier}/><span className={r.authority_status==="new"?"new-status":"ack-status"}>{r.authority_status==="new"?"NEW":"ACKNOWLEDGED"}</span><div className="row-actions"><button onClick={()=>setSelectedReport(r)}>Inspect</button>{r.authority_status==="new"?<button className="primary" onClick={()=>acknowledge(r.id)}>Acknowledge</button>:<span className="ack-check">✓ Recorded</span>}</div></div>)}</div>{!reports.length&&<div className="empty">No reports have arrived yet.</div>}{selectedReport&&<ReportInspector report={selectedReport} close={()=>setSelectedReport(null)} openConcern={openConcern} acknowledge={acknowledge} integrity={integrity} session={session}/>}</section>}
function ReportInspector({report,close,openConcern,acknowledge,integrity,session}){const [note,setNote]=useState("");const[cls,setCls]=useState("normal_signal");const[analysis,setAnalysis]=useState(null);const[outcome,setOutcome]=useState("pattern_confirmed");const[loading,setLoading]=useState(false);const[integrityBusy,setIntegrityBusy]=useState(false);const[integritySaved,setIntegritySaved]=useState(false);const[verificationSaved,setVerificationSaved]=useState(false);useEffect(()=>{
  // A report drawer is a new working context. Never carry unsaved review choices
  // (including Pattern confirmed / not confirmed) into another report.
  setNote("");
  setCls("normal_signal");
  setOutcome("pattern_confirmed");
  setAnalysis(null);
  setIntegritySaved(false);
  setVerificationSaved(false);
  authApi(`/api/authority/reports/${report.id}/analysis`,session.token).then(setAnalysis).catch(()=>setAnalysis(null));
},[report.id]);const saveIntegrity=async()=>{setIntegrityBusy(true);try{const ok=await integrity(report.id,cls,note);if(ok)setIntegritySaved(true)}finally{setIntegrityBusy(false)}};const saveVerification=async()=>{setLoading(true);try{await authApi(`/api/authority/reports/${report.id}/verification`,session.token,{method:"POST",body:{outcome,note}});setVerificationSaved(true)}catch(e){}finally{setLoading(false)}};return <div className="drawer-backdrop"><aside className="drawer"><button className="close" onClick={close}>×</button><span className="eyebrow pink">REPORT REVIEW</span><h2>{report.category_label}</h2><div className="drawer-id">{report.id}</div><div className="drawer-facts"><div><span>Location</span><strong>{report.location_label}</strong></div><div><span>Received</span><strong>{new Date(report.received_at).toLocaleString()}</strong></div><div><span>Reporter mode</span><strong>{report.reporter_type==="witness"?"Witness":"Self"}</strong></div><div><span>Assigned authority</span><strong>{report.assigned_authority||authorityFallback}</strong></div><div><span>Pattern tier</span><Status tier={report.tier}/></div></div><div className="review-warning"><strong>Do not treat this report as proof against a person.</strong><span>SafeLine supports location/pattern decisions. A report cannot establish individual guilt.</span></div><div className="drawer-section"><span className="eyebrow">REPORT ANALYSIS</span><h3>Attention review</h3>{analysis?<><div className="ai-score"><strong>Review</strong><span>{analysis.summary}</span></div>{analysis.flags?.length?<div className="flag-list">{analysis.flags.map(f=><span key={f}>{f.replaceAll("_"," ")}</span>)}</div>:<div className="notice">No obvious note anomaly detected.</div>}</>:<div className="notice">Analyzing optional report context…</div>}</div><div className="drawer-section"><span className="eyebrow">SIGNAL INTEGRITY</span><select value={cls} onChange={e=>setCls(e.target.value)}><option value="normal_signal">Normal signal</option><option value="needs_verification">Needs verification</option><option value="duplicate">Possible duplicate</option><option value="coordinated_pattern">Possible coordinated pattern</option><option value="insufficient_information">Insufficient information</option></select><textarea value={note} onChange={e=>setNote(e.target.value)} placeholder="Why did you classify it this way?"/><button className="secondary full" disabled={integrityBusy} onClick={saveIntegrity}>{integrityBusy?"Saving…":"Record integrity review"}</button>{integritySaved&&<div className="action-confirmation">✓ Integrity review recorded</div>}</div><div className="drawer-section"><span className="eyebrow">AUTHORITY VERIFICATION</span><select value={outcome} onChange={e=>setOutcome(e.target.value)}><option value="pattern_confirmed">Pattern confirmed</option><option value="pattern_not_confirmed">Pattern not confirmed</option><option value="insufficient_evidence">Insufficient evidence</option><option value="context_explains">Context explains activity</option><option value="reporting_integrity_concern">Reporting integrity concern</option></select><button className="secondary full" disabled={loading} onClick={saveVerification}>{loading?"Saving…":"Save verification outcome"}</button>{verificationSaved&&<div className="action-confirmation">✓ Verification recorded</div>}</div><div className="drawer-actions"><button className="primary" onClick={()=>{acknowledge(report.id);close()}}>Acknowledge report</button><button className="secondary" onClick={()=>{close();openConcern({alert_id:report.alert_id})}}>Open concern →</button></div></aside></div>}
function ActionQueue({actions,openConcern}){return <section className="workspace-card action-page"><div className="panel-head"><div><span className="eyebrow">ACCOUNTABILITY</span><h2>Action tracker</h2><p>Completion requires an observation plus approved evidence. Closed concerns remain auditable.</p></div><span className="inbox-live">{actions.length} RECORDS</span></div>{actions.length?<div className="action-grid">{actions.map(a=><button key={a.id} onClick={()=>openConcern({alert_id:a.id})}><div><Status tier={a.tier}/><span>{a.status.replaceAll("_"," ")}</span></div><h3>{a.location_label}</h3><p>{a.action_type||"Action not yet specified"}</p><small>Updated {new Date(a.updated_at).toLocaleString()}</small></button>)}</div>:<div className="empty">No authority actions have been started yet.</div>}</section>}
function MapView({map,assistance,acknowledgeHelp}){
  const points=useMemo(()=>map.reports.filter(p=>p.latitude!=null&&p.longitude!=null),[map.reports]);
  const branches=useMemo(()=>map.branches||[],[map.branches]);
  const [ready,setReady]=useState(false);
  useEffect(()=>{
    if(!window.L)return;const el=document.getElementById("authority-map");if(!el)return;const L=window.L;
    const center=branches[0]?[branches[0].latitude,branches[0].longitude]:(points[0]?[points[0].latitude,points[0].longitude]:[16.20,73.45]);
    const m=L.map(el).setView(center,branches.length?10:(points.length?12:8));
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{attribution:"© OpenStreetMap contributors"}).addTo(m);

    // Fixed prototype route requested for the demo: Achra incident -> nearest
    // Malvan authority, approximately 7.2 km. This is deliberately the only
    // incident-to-authority connection line shown on the map.
    const demoIncident={latitude:16.1200,longitude:73.4700,label:"Achra, Malvan",category_label:"Demo incident"};
    const malvan=branches.find(b=>/Malvan Authority/i.test(b.name)&&b.zone_name!=="Achra / Malvan North") || branches.find(b=>/Malvan/i.test(b.name));
    if(malvan){
      const demoDistance=7.2;
      L.circleMarker([demoIncident.latitude,demoIncident.longitude],{radius:8,color:"#ef4444",weight:2,fillColor:"#ef4444",fillOpacity:.92})
        .bindPopup(`<strong>Incident location</strong><br>Achra, Malvan<br>Demo incident<br><br><strong>Auto-routed authority</strong><br>${escapeHtml(malvan.name)}<br>${demoDistance.toFixed(1)} km away`).addTo(m);
      L.polyline([[demoIncident.latitude,demoIncident.longitude],[malvan.latitude,malvan.longitude]],{color:"#ff5d91",weight:3,dashArray:"6 7",opacity:.8})
        .bindTooltip("Achra → nearest authority · 7.2 km",{sticky:true}).addTo(m);
    }

    const assignedBranchIds=new Set(points.map(p=>{
      const nearest=branches.length?branches.map(b=>({...b,distance:distanceM({lat:p.latitude,lng:p.longitude},{lat:b.latitude,lng:b.longitude})})).sort((a,c)=>a.distance-c.distance)[0]:null;
      return nearest?.id;
    }).filter(Boolean));
    branches.forEach(b=>{
      const nearestIncident=points.length?points.map(p=>({...p,distance:distanceM({lat:b.latitude,lng:b.longitude},{lat:p.latitude,lng:p.longitude})})).sort((a,c)=>a.distance-c.distance)[0]:null;
      const isAssigned=assignedBranchIds.has(b.id);
      const branchColor=isAssigned?"#ff5d91":"#3b82f6";
      const label=`<strong>${isAssigned?"Nearest / assigned demo authority":"Demo authority branch"}</strong><br>${escapeHtml(b.name)}${nearestIncident?`<br>${Math.round(nearestIncident.distance/1000*10)/10} km to nearest incident`:""}`;
      L.circleMarker([b.latitude,b.longitude],{radius:isAssigned?9:7,color:branchColor,weight:2,fillColor:branchColor,fillOpacity:.9}).bindPopup(label).addTo(m);
    });
    points.forEach(p=>{
      L.circleMarker([p.latitude,p.longitude],{radius:8,color:"#ef4444",weight:2,fillColor:"#ef4444",fillOpacity:.92}).bindPopup(`<strong>Incident location</strong><br>${escapeHtml(p.location_label)}<br>${escapeHtml(p.category_label)}${p.assigned_authority?`<br><br><strong>Auto-routed authority</strong><br>${escapeHtml(p.assigned_authority)}`:""}`).addTo(m);
    });
    assistance.forEach(a=>L.circleMarker([a.latitude,a.longitude],{radius:11,weight:3,fillOpacity:.18}).bindPopup(`<strong>HELP REQUEST</strong><br>${escapeHtml(a.request_id||a.id)}<br>${escapeHtml(a.location_label)}`).addTo(m));
    const allCoords=[...branches.map(b=>[b.latitude,b.longitude]),...points.slice(0,20).map(p=>[p.latitude,p.longitude]),[demoIncident.latitude,demoIncident.longitude]];
    if(allCoords.length>1) m.fitBounds(L.latLngBounds(allCoords),{padding:[28,28],maxZoom:13});
    setReady(true);return()=>m.remove();
  },[points,assistance,branches]);
  return <div className="map-page">
    <div className="section-title-row"><div><span className="eyebrow">LOCATION INTELLIGENCE</span><h2>Incident + authority map</h2><p>Incident location is the one-time report point. Cases are automatically routed using location jurisdiction data.</p></div><span className="muted">{points.length} incidents · {branches.length} demo branches</span></div>
    <div className="map-demo-note">Demo authority locations and the Achra → Malvan 7.2 km route are synthetic prototype data, not real operational branch locations.</div>
    <div className="map-layout"><div id="authority-map" className="map-canvas">{!ready&&<div className="map-loading">Loading map…</div>}</div>
      <div className="map-side">
        <div className="map-legend"><div><span className="legend-dot incident-dot"></span><span><strong>Incident location</strong><small>Stored with the report — not live tracking</small></span></div><div><span className="legend-dot authority-nearest-dot"></span><span><strong>Nearest / assigned authority</strong><small>Pink = branch selected by location routing</small></span></div><div><span className="legend-dot authority-other-dot"></span><span><strong>Other demo authorities</strong><small>Registered nearby branches</small></span></div></div>
        <div className="map-side-head"><span className="eyebrow">DEMO ROUTE</span><strong>Achra → Malvan Authority</strong><small>7.2 km · connection line shown</small></div>
        <div className="map-side-head second"><span className="eyebrow">AUTHORITY COVERAGE</span><strong>{branches.length} demo branches</strong></div>
        {branches.map(b=><div className="map-item" key={b.id}><strong>{b.name}</strong><span>Demo branch · {b.role||"Authority"}</span></div>)}
        <div className="map-side-head second"><span className="eyebrow">LATEST INCIDENTS</span></div>
        {points.slice(0,10).map(p=><div className="map-item" key={p.id}><strong>{p.location_label}</strong><span>{p.category_label} · {p.location_source||"stored"}</span><small>{timeAgo(p.received_at)}</small></div>)}
      </div>
    </div>
  </div>;
}

function Integrity({session}){
  const[scenario,setScenario]=useState("genuine_slow_build");const[volume,setVolume]=useState(32);const[minutes,setMinutes]=useState(240);const[diversity,setDiversity]=useState(70);const[locationSpread,setLocationSpread]=useState(20);const[result,setResult]=useState(null);const[loading,setLoading]=useState(false);const[history,setHistory]=useState([]);
  const scenarios={genuine_slow_build:["Genuine slow build","Multiple reporters and times gradually rise above local activity."],coordinated_flood:["Coordinated flood","High-volume burst with concentrated timing and sources."],mixed_genuine_coordinated:["Mixed genuine + coordinated","Real activity mixed with an artificial reporting burst."],one_reporter_repeat:["One reporter repeating","Repeated submissions from one pseudonymous source."],festival_event_spike:["Festival / event spike","A real contextual event produces a temporary reporting increase."],cold_start:["New location / cold start","A new location has little local history."],cross_spot_corridor:["Cross-spot corridor","Activity appears across adjacent locations rather than one spot."],post_intervention:["Post-intervention monitoring","Activity changes after a preventive action."],adaptive_attacker:["Adaptive attacker","A coordinated source changes timing, diversity and locations to evade simple thresholds."],patient_spaced_flood:["Patient spaced-out flood","Submissions are deliberately spaced to bypass a short burst detector."]};
  const run=async()=>{setLoading(true);try{const r=await authApi("/api/authority/attack-lab",session.token,{method:"POST",body:JSON.stringify({scenario,volume,minutes,reporter_diversity:diversity,location_spread:locationSpread})});setResult(r);setHistory(h=>[{...r,run_at:new Date().toISOString()},...h].slice(0,6));}catch(e){setResult({interpretation:e.message})}finally{setLoading(false)}};
  return <section className="workspace-card integrity-page">
    <div className="panel-head"><div><span className="eyebrow">TOOLS · ISOLATED TEST SPACE</span><h2>Signal Integrity & Attack Lab</h2><p>Run adversarial and real-world scenarios against the same integrity principles. Nothing here changes production cases, baselines or authority status.</p></div><span className="inbox-live">NO PRODUCTION WRITE</span></div>
    <div className="integrity-grid"><Info title="Repeated source" value="Decay + cap" text="Repeated submissions lose influence rather than becoming independent incidents."/><Info title="Occurrence model" value="Episode capped" text="Multiple reports inside one occurrence cannot manufacture multiple episodes."/><Info title="Diversity" value="Multi-factor" text="Timing, source diversity and spatial spread are examined together."/><Info title="Human review" value="Always required" text="The lab never labels a person or report as true or false."/></div>
    <div className="lab-layout"><div className="lab-controls"><span className="eyebrow">SCENARIO SIMULATOR</span><label>Scenario<select value={scenario} onChange={e=>setScenario(e.target.value)}>{Object.entries(scenarios).map(([v,[l]])=><option key={v} value={v}>{l}</option>)}</select></label><p className="scenario-description">{scenarios[scenario][1]}</p><label>Submissions<input type="number" min="1" max="250" value={volume} onChange={e=>setVolume(Math.max(1,Math.min(250,Number(e.target.value)||1)))}/></label><label>Time spread (minutes)<input type="number" min="1" max="10080" value={minutes} onChange={e=>setMinutes(Math.max(1,Math.min(10080,Number(e.target.value)||1)))}/></label><label>Reporter diversity<input type="range" min="5" max="100" value={diversity} onChange={e=>setDiversity(Number(e.target.value))}/><span className="range-value">{diversity}% distinct-source tendency</span></label><label>Location spread<input type="range" min="0" max="100" value={locationSpread} onChange={e=>setLocationSpread(Number(e.target.value))}/><span className="range-value">{locationSpread}% cross-location tendency</span></label><button className="primary full" onClick={run}>{loading?"Running isolated test…":"Run scenario"}</button></div>
      <div className="lab-result"><span className="eyebrow">PIPELINE INSPECTOR</span>{result?<><div className="lab-stage-row"><span>RAW</span><strong>{result.raw_reports}</strong><small>submissions</small></div><div className="lab-stage-row"><span>INTEGRITY</span><strong>{result.distinct_tokens}</strong><small>distinct sources</small></div><div className="lab-stage-row"><span>OCCURRENCES</span><strong>{result.occurrences ?? "—"}</strong><small>grouped episodes</small></div><div className="lab-stage-row"><span>EFFECTIVE SIGNAL</span><strong>{result.effective_signal}</strong><small>influence after controls</small></div><div className="flag-list">{(result.flags||[]).map(f=><span key={f}>{f}</span>)}</div><div className="lab-interpretation"><strong>Interpretation</strong><p>{result.interpretation}</p></div><div className="lab-honesty"><strong>Boundary</strong><span>{result.boundary||"This test evaluates signal influence, not whether an individual report is truthful."}</span></div></>:<div className="lab-placeholder"><strong>RAW → INTEGRITY → OCCURRENCES → TIME + SPACE → BASELINE → CONTEXT → DECISION</strong><span>Run a scenario to inspect how the signal changes at each stage.</span></div>}</div></div>
    {history.length>0&&<div className="lab-history"><div className="section-title-row"><div><span className="eyebrow">RUN HISTORY</span><h3>Recent isolated tests</h3></div></div>{history.map((h,i)=><div className="lab-history-row" key={h.run_at+i}><strong>{scenarios[h.scenario]?.[0]||h.scenario}</strong><span>{h.raw_reports} reports · {h.distinct_tokens} sources · signal {h.effective_signal}</span><small>{new Date(h.run_at).toLocaleString()}</small></div>)}</div>}
    <div className="architecture-line">Report <b>→</b> Signal integrity <b>→</b> Occurrences <b>→</b> Time + space <b>→</b> Baseline + context <b>→</b> Decision gate <b>→</b> Human review</div><p className="honesty">SafeLine reduces disproportionate influence from repetitive or coordinated submissions. It does not prove anonymous reports true or false and it does not identify an offender.</p>
  </section>;
}

function ContextEvents({session}){const[events,setEvents]=useState([]);const[spotsForContext,setSpotsForContext]=useState([]);const[name,setName]=useState("");const[start,setStart]=useState("");const[end,setEnd]=useState("");const[spotChoice,setSpotChoice]=useState("");const[msg,setMsg]=useState("");const load=()=>authApi("/api/context-events",session.token).then(setEvents).catch(e=>setMsg(e.message));useEffect(()=>{load();api("/api/spots").then(setSpotsForContext).catch(()=>{})},[]);const save=async()=>{try{await authApi("/api/context-events",session.token,{method:"POST",body:JSON.stringify({name,start_at:new Date(start).toISOString(),end_at:new Date(end).toISOString(),spot_id:spotChoice||null})});setName("");setStart("");setEnd("");setSpotChoice("");setMsg("Context event recorded and scoring refreshed.");load()}catch(e){setMsg(e.message)}};return <section className="workspace-card settings-page"><div className="panel-head"><div><span className="eyebrow">BASELINE + CONTEXT</span><h2>Context events</h2><p>Record festivals, construction, exams or other known events so a legitimate spike is not automatically treated as deterioration.</p></div></div><div className="context-form"><input value={name} onChange={e=>setName(e.target.value)} placeholder="Event name"/><select value={spotChoice} onChange={e=>setSpotChoice(e.target.value)} aria-label="Context location"><option value="">All locations</option>{spotsForContext.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select><input type="datetime-local" value={start} onChange={e=>setStart(e.target.value)}/><input type="datetime-local" value={end} onChange={e=>setEnd(e.target.value)}/><button className="primary" disabled={!name||!start||!end} onClick={save}>Add context event</button></div>{msg&&<div className="notice">{msg}</div>}<div className="context-list">{events.map(e=><div className="context-row" key={e.id}><strong>{e.name}</strong><span>{new Date(e.start_at).toLocaleString()} → {new Date(e.end_at).toLocaleString()}</span><small>{e.location_key?e.location_key:"All locations"} · {e.id}</small></div>)}{!events.length&&<div className="empty">No context events recorded.</div>}</div></section>}
function AuthoritySettings({session,settings,updateSetting,onLogout}){return <section className="workspace-card settings-page"><div className="panel-head"><div><span className="eyebrow">CONTROL ROOM</span><h2>Authority settings</h2><p>Demo station configuration and workspace preferences.</p></div></div><div className="profile-card"><div className="profile-mark">{session.name.split(" ").map(x=>x[0]).slice(0,2).join("")}</div><div><strong>{session.name}</strong><span>{session.police_id} · {session.role}</span><small>{session.station}</small></div></div><div className="settings-list"><label><span><strong>Auto-refresh</strong><small>Keep the authority inbox live every 4 seconds.</small></span><input type="checkbox" checked={settings.autoRefresh} onChange={e=>updateSetting("autoRefresh",e.target.checked)}/></label><label><span><strong>Compact workspace</strong><small>Use denser evidence rows on smaller screens.</small></span><input type="checkbox" checked={settings.compact} onChange={e=>updateSetting("compact",e.target.checked)}/></label></div><div className="security-note"><strong>Demo authentication</strong><span>Demo role separation is enforced: a duty officer cannot approve their own evidence, and only a Station Supervisor can approve completion evidence. Production deployment would require the department's identity provider, role permissions and audit controls.</span></div><button className="secondary" onClick={onLogout}>Sign out</button></section>}
function Metric({label,value,tone}){return <div className={`metric ${tone||""}`}><span>{label}</span><strong>{value}</strong></div>}
function Info({title,value,text}){return <div className="info"><span>{title}</span><strong>{value}</strong><small>{text}</small></div>}
function formatTimer(s){const m=Math.floor(s/60);const sec=s%60;return `${String(m).padStart(2,"0")}:${String(sec).padStart(2,"0")}`}
function timeAgo(iso){const ms=Date.now()-new Date(iso).getTime();const sec=Math.max(1,Math.floor(ms/1000));if(sec<60)return `${sec}s ago`;const min=Math.floor(sec/60);if(min<60)return `${min}m ago`;const h=Math.floor(min/60);if(h<24)return `${h}h ago`;return `${Math.floor(h/24)}d ago`}
function escapeHtml(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]))}
function App(){const[path,setPath]=useState(location.pathname);const go=p=>{history.pushState({},"",p);setPath(p)};useEffect(()=>{const f=()=>setPath(location.pathname);addEventListener("popstate",f);return()=>removeEventListener("popstate",f)},[]);return path.startsWith("/authority")?<Authority go={go}/>:<Citizen go={go}/>}
createRoot(document.getElementById("root")).render(<App/>);
