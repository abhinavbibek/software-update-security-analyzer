// frontend/src/App.jsx
import React, { useEffect, useState, useRef } from "react";
import axios from "axios";
import ReportViewer from "./components/ReportViewer";
import ReactMarkdown from "react-markdown";
import Header from "./components/Header";

const BACKEND = import.meta.env.VITE_BACKEND_URL || "";

function joinBase(p) {
  if (!p) return p;
  if (!BACKEND) return p;
  if (!p.startsWith("/")) p = "/" + p;
  return `${BACKEND}${p}`;
}

export default function App() {
  const [analysisStarted, setAnalysisStarted] = useState(false);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const cooldownRef = useRef(null);

  const [checkMsg, setCheckMsg] = useState("Checking for updates...");
  const [updateAvailable, setUpdateAvailable] = useState(false);
  const [availableVersion, setAvailableVersion] = useState(null);

  const [runs, setRuns] = useState({});
  const [completeVersions, setCompleteVersions] = useState({ v1: false, v2: false });

  const [v1HtmlExists, setV1HtmlExists] = useState(false);
  const [v2HtmlExists, setV2HtmlExists] = useState(false);
  const [v1JsonExists, setV1JsonExists] = useState(false);
  const [v2JsonExists, setV2JsonExists] = useState(false);

  const [aiMd, setAiMd] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);

  const pollRef = useRef({});

  const reportDirV1 = "/reports/current_run/notepad_v1_update/reports";
  const reportDirV2 = "/reports/current_run/notepad_v2_update/reports";
  const deepJsonV1 = `${reportDirV1}/deep_analysis.json`;
  const deepJsonV2 = `${reportDirV2}/deep_analysis.json`;
  const fullHtmlV1 = `${reportDirV1}/full_report.html`;
  const fullHtmlV2 = `${reportDirV2}/full_report.html`;

  const resourceExists = async (path) => {
    try {
      const res = await axios.get(joinBase(path), { validateStatus: () => true });
      return res.status >= 200 && res.status < 300;
    } catch {
      return false;
    }
  };

  // -----------------------------
  // CHECK UPDATE POLLING
  // -----------------------------
  useEffect(() => {
    let cancelled = false;

    async function pollCheck() {
      try {
        const r = await axios.get(joinBase("/check_update"));
        const data = r.data || {};
        if (cancelled) return;

        if (data.update_available) {
          setUpdateAvailable(true);
          setAvailableVersion(data.available_version);
        } else {
          setUpdateAvailable(false);
          setAvailableVersion(null);
        }

        if (data.message) setCheckMsg(data.message);
      } catch (e) {
        console.warn("check_update failed", e);
      }
    }

    pollCheck();
    const t = setInterval(pollCheck, 2500);

    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  // -----------------------------
  // FILE POLLING
  // -----------------------------
  useEffect(() => {
    let cancelled = false;

    async function pollFiles() {
      if (cancelled) return;

      try {
        const [h1, h2, j1, j2] = await Promise.all([
          resourceExists(fullHtmlV1),
          resourceExists(fullHtmlV2),
          resourceExists(deepJsonV1),
          resourceExists(deepJsonV2),
        ]);

        if (!cancelled && analysisStarted) {
          setV1HtmlExists(h1);
          setV2HtmlExists(h2);
          setV1JsonExists(j1);
          setV2JsonExists(j2);

          if (h1) setCompleteVersions((p) => ({ ...p, v1: true }));
          if (h2) setCompleteVersions((p) => ({ ...p, v2: true }));
        }
      } catch (e) {
        console.warn("file poll error", e);
      } finally {
        if (!cancelled) pollRef.current.files = setTimeout(pollFiles, 2500);
      }
    }

    pollFiles();
    return () => {
      cancelled = true;
      if (pollRef.current.files) clearTimeout(pollRef.current.files);
    };
  }, [analysisStarted]);

  // -----------------------------
  // START ANALYSIS
  // -----------------------------
  const startAnalysis = async () => {
    setAnalysisStarted(true);
    setAnalysisRunning(true);
    setUpdateAvailable(false);
    setAiError(null);
    setAiMd(null);

    try {
      const r = await axios.post(
        joinBase("/apply_update"),
        new URLSearchParams({ version: availableVersion }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      const runId = r.data?.run_id;
      if (!runId) {
        setCheckMsg("Analysis started — run ID missing.");
        return;
      }

      setRuns((prev) => ({
        ...prev,
        [runId]: { run_id: runId, version: availableVersion, status: "running" },
      }));

      setCheckMsg(`Analysis started for V${availableVersion}`);
      pollProgress(runId);
    } catch (e) {
      console.error("apply_update failed", e);
      setCheckMsg("Failed to start analysis.");
      setAnalysisRunning(false);
    }
  };

  // -----------------------------
  // PROGRESS POLLING
  // -----------------------------
  const pollProgress = (runId) => {
    let cancelled = false;

    const tick = async () => {
      if (cancelled) return;

      try {
        const r = await axios.get(joinBase(`/progress/${runId}`), { validateStatus: () => true });
        const data = r.data || {};
        const status = (data.status || "").toLowerCase();

        setRuns((prev) => ({
          ...prev,
          [runId]: { ...(prev[runId] || {}), status, version: data.version },
        }));

        if (analysisRunning && data.message) setCheckMsg(data.message);

        if (data.percent >= 100 || ["completed", "finished", "done", "success"].includes(status)) {
          setAnalysisRunning(false);
          cooldownRef.current = Date.now() + 2500;
          setTimeout(() => (cooldownRef.current = null), 2500);
          return;
        }

        if (["error", "failed"].includes(status)) {
          setCheckMsg("Analysis failed.");
          setAnalysisRunning(false);
          return;
        }
      } catch {
      } finally {
        if (!cancelled) pollRef.current[runId] = setTimeout(tick, 1200);
      }
    };

    tick();
    return () => {
      cancelled = true;
      if (pollRef.current[runId]) clearTimeout(pollRef.current[runId]);
    };
  };

  // -----------------------------
  // AI ANALYSIS
  // -----------------------------
  const runAiAnalysis = async () => {
    setAiLoading(true);
    setAiError(null);
    setAiMd(null);

    try {
      const r = await axios.post(joinBase("/ai_analyze"), {}, { timeout: 300000 });
      if (r.data?.md) setAiMd(r.data.md);
      else setAiMd(JSON.stringify(r.data, null, 2));
    } catch (e) {
      setAiError(String(e));
    } finally {
      setAiLoading(false);
    }
  };

  const anyRunCompleted = completeVersions.v1 || completeVersions.v2;
  const canAiAnalyze = v1JsonExists && v2JsonExists;

  // Determine button layout for ReportViewer
  const buttonLayout =
    v1HtmlExists && v2HtmlExists
      ? "flex-row gap-6"
      : "flex-col gap-4";

  return (
    
    <div className="min-h-screen bg-gradient-to-br from-[#071025] to-[#07182a] p-8 text-gray-100 flex justify-center">
      <div className="w-full max-w-5xl flex flex-col gap-8">

        {/* HEADER */}
        <Header subtitle="Advanced Software Update Integrity Analyzer" />
      
        {/* MAIN GRID / SECTIONS */}
        <main className="grid grid-cols-1 gap-8">

          {/* UPDATE STATUS */}
          <section className="card w-full">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="card-title">Update Status</h3>
                <p className="text-sm text-gray-300">{checkMsg}</p>
              </div>

              <div className="text-right">
                {analysisRunning && (
                  <div className="flex items-center gap-2">
                    <div className="animate-spin h-5 w-5 border-2 border-amber-300 border-t-transparent rounded-full"></div>
                    <div className="text-amber-300 text-sm">Processing update…</div>
                  </div>
                )}
              </div>
            </div>

            {updateAvailable && availableVersion && !analysisRunning && (
              <div className="mt-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div className="text-sm text-gray-200">
                  New version available:{" "}
                  <strong className="text-indigo-200">v{availableVersion}</strong>
                </div>

                <div className="flex items-center gap-3">
                  <button onClick={startAnalysis} className="action-btn">
                    Analyze Update
                  </button>
                </div>
              </div>
              
            )}
          </section>

          {/* REPORT VIEWER */}
          {analysisStarted && anyRunCompleted && (
            <section className="card w-full">
              <h3 className="card-title">Reports</h3>
              <div className={`mt-4 flex ${buttonLayout} items-center justify-center`}>
                <ReportViewer
                  reportReadyV1={v1HtmlExists}
                  reportReadyV2={v2HtmlExists}
                  reportCompleteV1={completeVersions.v1}
                  reportCompleteV2={completeVersions.v2}
                  reportDirV1={joinBase(reportDirV1)}
                  reportDirV2={joinBase(reportDirV2)}
                />
              </div>
            </section>
          )}

          {/* AI ANALYSIS */}
          {analysisStarted && anyRunCompleted && (
            <section className="card w-full">
              <h3 className="card-title">AI Analysis</h3>
              <p className="text-sm text-gray-400 mb-3">
                AI forensic analysis on v1 & v2 deep_analysis.json
              </p>

              <button
                onClick={runAiAnalysis}
                disabled={!canAiAnalyze || aiLoading}
                className={`action-btn ${(!canAiAnalyze || aiLoading) ? "opacity-60 cursor-not-allowed" : ""}`}
              >
                {aiLoading ? "Running AI Analysis..." : "Run AI Analysis"}
              </button>

              {aiError && <div className="text-red-400 mt-3">Error: {aiError}</div>}

              {aiMd ? (
                <div className="mt-4 text-left prose max-w-full bg-[#06111e] p-4 rounded">
                  <ReactMarkdown>{aiMd}</ReactMarkdown>
                </div>
              ) : (
                <div className="text-gray-500 mt-3">No AI report generated yet.</div>
              )}
            </section>
          )}

        </main>
      </div>
    </div>
  );
}
