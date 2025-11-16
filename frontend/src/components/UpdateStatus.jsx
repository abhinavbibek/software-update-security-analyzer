// frontend/src/components/UpdateStatus.jsx
import { motion } from "framer-motion";

export default function UpdateStatus({ state, onApply }) {
  const st = state || {};
  const { status = "unknown", current_version = "-", available_version = "-", last_checked = Date.now() } = st;

  const getBadge = () => {
    const colors = {
      up_to_date: "bg-emerald-600",
      update_available: "bg-yellow-600",
      analyzing: "bg-blue-600",
      updated_benign: "bg-emerald-500",
      updated_malicious: "bg-red-500",
    };

    return (
      <span
        className={`px-3 py-1 rounded-full text-xs font-semibold shadow-sm ${
          colors[status] || "bg-gray-500"
        }`}
      >
        {String(status).replace("_", " ")}
      </span>
    );
  };

  return (
    <div className="card">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="card-title">Update Status {getBadge()}</h3>

          <p className="text-gray-300 text-sm mb-1">
            Current version: <b>{current_version}</b>
          </p>

          <p className="text-gray-400 text-sm mb-1">
            Available version:{" "}
            <b className="text-indigo-300">{available_version}</b>
          </p>

          <p className="text-gray-500 text-xs mt-2 italic">
            Last checked: {new Date(last_checked).toLocaleString()}
          </p>
        </div>

        <div className="flex items-start">
          {status === "update_available" && (
            <motion.button
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.94 }}
              onClick={onApply}
              className="mt-2 action-btn"
            >
              Apply Update & Analyze
            </motion.button>
          )}

          {status === "updated_benign" && (
            <div className="text-emerald-400 mt-3 font-medium">
              System updated successfully ✓
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
