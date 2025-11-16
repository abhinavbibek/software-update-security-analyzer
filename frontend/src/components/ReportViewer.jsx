// frontend/src/components/ReportViewer.jsx
import React from "react";
import { motion } from "framer-motion";

export default function ReportViewer({
  reportReadyV1 = false,
  reportReadyV2 = false,
  reportCompleteV1 = false,
  reportCompleteV2 = false,
  reportDirV1,
  reportDirV2,
}) {
  if (!reportCompleteV1 && !reportCompleteV2) return null;

  const bothDone = reportCompleteV1 && reportCompleteV2;
  const bothReady = reportReadyV1 && reportReadyV2;

  return (
    <motion.div
      className="rounded-lg p-4 bg-[#0c1124] border border-[#1f2b4a] w-full"
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      <h3 className="card-title mb-4">Full Reports</h3>

      <div
        className={
          bothDone
            ? "flex flex-row gap-6 justify-center"
            : "flex flex-col gap-4 items-center"
        }
      >
        {/* ---- V1 ---- */}
        {reportCompleteV1 ? (
          reportReadyV1 ? (
            <a
              href={reportDirV1}
              target="_blank"
              rel="noopener noreferrer"
              className="action-btn w-56 text-center"
            >
              View Full Report (v1)
            </a>
          ) : (
            <div className="text-gray-400">View Full Report (v1) — preparing…</div>
          )
        ) : (
          <div className="text-gray-500">View Full Report (v1) — waiting</div>
        )}

        {/* ---- V2 ---- */}
        {reportCompleteV2 ? (
          reportReadyV2 ? (
            <a
              href={reportDirV2}
              target="_blank"
              rel="noopener noreferrer"
              className="action-btn w-56 text-center"
            >
              View Full Report (v2)
            </a>
          ) : (
            <div className="text-gray-400">View Full Report (v2) — preparing…</div>
          )
        ) : (
          <div className="text-gray-500">View Full Report (v2) — waiting</div>
        )}
      </div>
    </motion.div>
  );
}
