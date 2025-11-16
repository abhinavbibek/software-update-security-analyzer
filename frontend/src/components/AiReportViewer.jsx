// frontend/src/components/AiReportViewer.jsx
import React from "react";
import ReactMarkdown from "react-markdown";

export default function AiReportViewer({ aiMarkdown }) {
  if (!aiMarkdown) {
    return (
      <div className="card text-center text-gray-400">
        AI report not available
      </div>
    );
  }

  return (
    <div className="card">
      <h3 className="card-title">AI Forensic Analysis Report</h3>

      <div className="prose max-w-full bg-[#0a1425] p-4 rounded-lg border border-[#1a2640] mt-3">
        <ReactMarkdown>{aiMarkdown}</ReactMarkdown>
      </div>
    </div>
  );
}
