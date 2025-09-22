"use client";

import { useState } from "react";

export default function FindingsPage() {
  const [filter, setFilter] = useState("all");

  return (
    <div className="min-h-screen p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Security Findings</h1>
          <p className="text-gray-400">
            View and manage security vulnerabilities and findings
          </p>
        </div>

        {/* Filters */}
        <div className="mb-6">
          <div className="flex space-x-4">
            {["all", "critical", "high", "medium", "low"].map((severity) => (
              <button
                key={severity}
                onClick={() => setFilter(severity)}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  filter === severity
                    ? "bg-blue-600 text-white"
                    : "bg-white/10 text-gray-300 hover:bg-white/20"
                }`}
              >
                {severity.charAt(0).toUpperCase() + severity.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Findings List */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="text-center py-12">
            <div className="w-16 h-16 mx-auto mb-4 bg-gray-600 rounded-full flex items-center justify-center">
              <svg className="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">No Findings Yet</h3>
            <p className="text-gray-400 mb-6">
              Run a security scan to start discovering vulnerabilities
            </p>
            <button className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition-colors">
              Start Your First Scan
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}