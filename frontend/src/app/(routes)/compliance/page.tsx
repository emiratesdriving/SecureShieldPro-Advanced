"use client";

import { useState } from "react";

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState("all");

  const frameworks = [
    { id: "all", name: "All Frameworks", count: 24 },
    { id: "pci-dss", name: "PCI DSS", count: 8 },
    { id: "iso-27001", name: "ISO 27001", count: 12 },
    { id: "nist", name: "NIST", count: 4 },
  ];

  return (
    <div className="min-h-screen p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Compliance Reports</h1>
          <p className="text-gray-400">
            Monitor compliance with security frameworks and standards
          </p>
        </div>

        {/* Framework Selector */}
        <div className="mb-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {frameworks.map((framework) => (
              <button
                key={framework.id}
                onClick={() => setSelectedFramework(framework.id)}
                className={`p-4 rounded-lg border transition-all ${
                  selectedFramework === framework.id
                    ? "bg-blue-600 border-blue-500 text-white"
                    : "bg-white/10 border-white/20 text-gray-300 hover:bg-white/20"
                }`}
              >
                <div className="text-lg font-semibold">{framework.name}</div>
                <div className="text-sm opacity-80">{framework.count} controls</div>
              </button>
            ))}
          </div>
        </div>

        {/* Compliance Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Overall Score</h3>
              <div className="w-8 h-8 bg-green-600 rounded-full flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
              </div>
            </div>
            <div className="text-3xl font-bold text-white mb-2">87%</div>
            <div className="text-sm text-green-400">+5% from last month</div>
          </div>

          <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Passed Controls</h3>
              <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
            <div className="text-3xl font-bold text-white mb-2">21/24</div>
            <div className="text-sm text-gray-400">3 controls need attention</div>
          </div>

          <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Last Assessment</h3>
              <div className="w-8 h-8 bg-purple-600 rounded-full flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clipRule="evenodd" />
                </svg>
              </div>
            </div>
            <div className="text-3xl font-bold text-white mb-2">2 days</div>
            <div className="text-sm text-gray-400">ago</div>
          </div>
        </div>

        {/* Compliance Details */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
          <div className="text-center py-12">
            <div className="w-16 h-16 mx-auto mb-4 bg-gray-600 rounded-full flex items-center justify-center">
              <svg className="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
              </svg>
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">Compliance Details</h3>
            <p className="text-gray-400 mb-6">
              Detailed compliance reports will appear here
            </p>
            <button className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition-colors">
              Generate Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}