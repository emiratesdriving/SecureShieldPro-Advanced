"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("general");
  const [formData, setFormData] = useState({
    notifications: true,
    autoScan: false,
    reportEmail: "admin@company.com",
    scanSchedule: "weekly",
  });
  const router = useRouter();

  const handleLogout = () => {
    // Clear authentication data
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    
    // Redirect to login
    router.push("/auth/login");
  };

  const tabs = [
    { id: "general", name: "General", icon: "cog" },
    { id: "security", name: "Security", icon: "shield" },
    { id: "notifications", name: "Notifications", icon: "bell" },
    { id: "account", name: "Account", icon: "user" },
  ];

  return (
    <div className="min-h-screen p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
          <p className="text-gray-400">
            Configure your SecureShield Pro preferences
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Settings Navigation */}
          <div className="lg:col-span-1">
            <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-4">
              <nav className="space-y-2">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full text-left px-4 py-3 rounded-lg transition-colors ${
                      activeTab === tab.id
                        ? "bg-blue-600 text-white"
                        : "text-gray-300 hover:bg-white/10"
                    }`}
                  >
                    {tab.name}
                  </button>
                ))}
              </nav>
            </div>
          </div>

          {/* Settings Content */}
          <div className="lg:col-span-3">
            <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20 p-6">
              {activeTab === "general" && (
                <div>
                  <h2 className="text-xl font-semibold text-white mb-6">General Settings</h2>
                  <div className="space-y-6">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Report Email
                      </label>
                      <input
                        type="email"
                        value={formData.reportEmail}
                        onChange={(e) => setFormData({...formData, reportEmail: e.target.value})}
                        className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Scan Schedule
                      </label>
                      <select
                        value={formData.scanSchedule}
                        onChange={(e) => setFormData({...formData, scanSchedule: e.target.value})}
                        className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white"
                      >
                        <option value="daily">Daily</option>
                        <option value="weekly">Weekly</option>
                        <option value="monthly">Monthly</option>
                      </select>
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-white font-medium">Enable Auto Scan</h3>
                        <p className="text-gray-400 text-sm">Automatically scan for vulnerabilities</p>
                      </div>
                      <button
                        onClick={() => setFormData({...formData, autoScan: !formData.autoScan})}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          formData.autoScan ? "bg-blue-600" : "bg-gray-600"
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            formData.autoScan ? "translate-x-6" : "translate-x-1"
                          }`}
                        />
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "security" && (
                <div>
                  <h2 className="text-xl font-semibold text-white mb-6">Security Settings</h2>
                  <div className="space-y-6">
                    <div className="border border-white/20 rounded-lg p-4">
                      <h3 className="text-white font-medium mb-2">Two-Factor Authentication</h3>
                      <p className="text-gray-400 text-sm mb-4">Add an extra layer of security to your account</p>
                      <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium">
                        Enable 2FA
                      </button>
                    </div>

                    <div className="border border-white/20 rounded-lg p-4">
                      <h3 className="text-white font-medium mb-2">Change Password</h3>
                      <p className="text-gray-400 text-sm mb-4">Update your account password</p>
                      <button className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg font-medium">
                        Change Password
                      </button>
                    </div>

                    <div className="border border-white/20 rounded-lg p-4">
                      <h3 className="text-white font-medium mb-2">API Keys</h3>
                      <p className="text-gray-400 text-sm mb-4">Manage your API access keys</p>
                      <button className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg font-medium">
                        Manage Keys
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "notifications" && (
                <div>
                  <h2 className="text-xl font-semibold text-white mb-6">Notification Settings</h2>
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-white font-medium">Email Notifications</h3>
                        <p className="text-gray-400 text-sm">Receive security alerts via email</p>
                      </div>
                      <button
                        onClick={() => setFormData({...formData, notifications: !formData.notifications})}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          formData.notifications ? "bg-blue-600" : "bg-gray-600"
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            formData.notifications ? "translate-x-6" : "translate-x-1"
                          }`}
                        />
                      </button>
                    </div>

                    <div className="border border-white/20 rounded-lg p-4">
                      <h3 className="text-white font-medium mb-2">Notification Types</h3>
                      <div className="space-y-3">
                        {["Critical Vulnerabilities", "Scan Completion", "Compliance Changes", "System Updates"].map((type) => (
                          <label key={type} className="flex items-center">
                            <input
                              type="checkbox"
                              defaultChecked
                              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                            />
                            <span className="ml-2 text-gray-300">{type}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "account" && (
                <div>
                  <h2 className="text-xl font-semibold text-white mb-6">Account Settings</h2>
                  <div className="space-y-6">
                    <div className="border border-white/20 rounded-lg p-4">
                      <h3 className="text-white font-medium mb-2">Profile Information</h3>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-300 mb-2">First Name</label>
                          <input
                            type="text"
                            defaultValue="Admin"
                            className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-300 mb-2">Last Name</label>
                          <input
                            type="text"
                            defaultValue="User"
                            className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400 text-white"
                          />
                        </div>
                      </div>
                    </div>

                    <div className="border border-red-500/20 rounded-lg p-4">
                      <h3 className="text-red-400 font-medium mb-2">Danger Zone</h3>
                      <p className="text-gray-400 text-sm mb-4">These actions cannot be undone</p>
                      <div className="space-y-3">
                        <button
                          onClick={handleLogout}
                          className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg font-medium mr-3"
                        >
                          Sign Out
                        </button>
                        <button className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-medium">
                          Delete Account
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Save Button */}
              <div className="mt-8 pt-6 border-t border-white/20">
                <button className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium">
                  Save Changes
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}