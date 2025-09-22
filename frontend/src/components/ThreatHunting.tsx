import React, { useState, useEffect } from 'react';
import {
  ShieldExclamationIcon,
  EyeIcon,
  CpuChipIcon,
  ChartBarIcon,
  PlayIcon,
  PauseIcon,
  StopIcon,
  BoltIcon,
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  BeakerIcon,
  FireIcon
} from '@heroicons/react/24/outline';

interface ThreatIndicator {
  id: string;
  type: string;
  value: string;
  confidence: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  first_seen: string;
  last_seen: string;
  occurrences: number;
  related_indicators: string[];
}

interface ThreatHunt {
  id: string;
  name: string;
  category: string;
  status: 'ACTIVE' | 'COMPLETED' | 'PAUSED' | 'INVESTIGATING';
  confidence: number;
  priority: number;
  indicators_count: number;
  created_at: string;
  updated_at: string;
  assigned_analyst?: string;
}

interface SecurityEvent {
  id: string;
  type: string;
  source_ip?: string;
  destination_ip?: string;
  user?: string;
  timestamp: string;
  status: string;
}

interface ThreatMetrics {
  active_hunts: number;
  total_indicators: number;
  detection_rules: number;
  anomalies_detected: number;
  avg_hunt_confidence: number;
  system_health: number;
}

interface AttackSimulation {
  attack_type: string;
  intensity: 'low' | 'medium' | 'high';
  duration_minutes: number;
  events_generated: number;
  threats_detected: number;
  detection_rate: number;
}

const ThreatHunting: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'hunts' | 'indicators' | 'simulate'>('dashboard');
  const [hunts, setHunts] = useState<ThreatHunt[]>([]);
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [metrics, setMetrics] = useState<ThreatMetrics | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [simulation, setSimulation] = useState<AttackSimulation | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [loading, setLoading] = useState(false);

  // Load initial data
  useEffect(() => {
    loadDashboardData();
    loadActiveHunts();
    loadThreatIndicators();
    
    // Real-time updates
    const interval = setInterval(() => {
      loadDashboardData();
      loadActiveHunts();
    }, 10000); // Update every 10 seconds

    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      const response = await fetch('/api/v1/threat-hunting/analytics/dashboard');
      const data = await response.json();
      if (data.status === 'success') {
        setMetrics(data.dashboard.overview);
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    }
  };

  const loadActiveHunts = async () => {
    try {
      const response = await fetch('/api/v1/threat-hunting/hunts');
      const data = await response.json();
      if (data.status === 'success') {
        setHunts(data.hunts);
      }
    } catch (error) {
      console.error('Failed to load hunts:', error);
    }
  };

  const loadThreatIndicators = async () => {
    try {
      const response = await fetch('/api/v1/threat-hunting/indicators');
      const data = await response.json();
      if (data.status === 'success') {
        setIndicators(data.indicators);
      }
    } catch (error) {
      console.error('Failed to load indicators:', error);
    }
  };

  const processSecurityEvent = async (event: Partial<SecurityEvent>) => {
    try {
      setLoading(true);
      const response = await fetch('/api/v1/threat-hunting/events/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event)
      });
      
      const data = await response.json();
      if (data.status === 'processed') {
        // Add to events list
        setEvents(prev => [{
          ...event as SecurityEvent,
          id: data.event_id,
          timestamp: new Date().toISOString()
        }, ...prev.slice(0, 19)]); // Keep last 20 events
        
        // Refresh data
        loadActiveHunts();
        loadThreatIndicators();
      }
    } catch (error) {
      console.error('Failed to process event:', error);
    } finally {
      setLoading(false);
    }
  };

  const simulateAttack = async (attackType: string, intensity: 'low' | 'medium' | 'high', duration: number) => {
    try {
      setIsSimulating(true);
      const response = await fetch('/api/v1/threat-hunting/simulate/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attack_type: attackType,
          intensity,
          duration_minutes: duration
        })
      });
      
      const data = await response.json();
      if (data.status === 'simulation_completed') {
        setSimulation(data);
        loadDashboardData();
        loadActiveHunts();
      }
    } catch (error) {
      console.error('Attack simulation failed:', error);
    } finally {
      setIsSimulating(false);
    }
  };

  const updateHuntStatus = async (huntId: string, newStatus: string, analyst?: string) => {
    try {
      const response = await fetch(`/api/v1/threat-hunting/hunts/${huntId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus, analyst })
      });
      
      if (response.ok) {
        loadActiveHunts();
      }
    } catch (error) {
      console.error('Failed to update hunt status:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-600 bg-red-100';
      case 'HIGH': return 'text-orange-600 bg-orange-100';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-100';
      case 'LOW': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'ACTIVE': return <PlayIcon className="h-4 w-4 text-green-600" />;
      case 'PAUSED': return <PauseIcon className="h-4 w-4 text-yellow-600" />;
      case 'COMPLETED': return <StopIcon className="h-4 w-4 text-blue-600" />;
      case 'INVESTIGATING': return <MagnifyingGlassIcon className="h-4 w-4 text-purple-600" />;
      default: return <EyeIcon className="h-4 w-4 text-gray-600" />;
    }
  };

  return (
    <div className="threat-hunting p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center">
            <ShieldExclamationIcon className="h-8 w-8 mr-3 text-red-600" />
            Advanced Threat Hunting
          </h1>
          <p className="text-gray-600 mt-1">Real-time behavioral analytics and automated threat detection</p>
        </div>
        
        <div className="flex space-x-3">
          <button
            onClick={() => loadDashboardData()}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Refresh Data
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex space-x-1 mb-6 bg-gray-100 p-1 rounded-lg">
        {[
          { id: 'dashboard', label: 'Dashboard', icon: ChartBarIcon },
          { id: 'hunts', label: 'Active Hunts', icon: EyeIcon },
          { id: 'indicators', label: 'Threat Indicators', icon: ExclamationTriangleIcon },
          { id: 'simulate', label: 'Attack Simulation', icon: BeakerIcon }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center px-4 py-2 rounded-md transition-colors ${
              activeTab === tab.id
                ? 'bg-white text-blue-600 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Dashboard Tab */}
      {activeTab === 'dashboard' && (
        <div className="space-y-6">
          {/* Metrics Cards */}
          {metrics && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Active Hunts</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.active_hunts}</p>
                  </div>
                  <EyeIcon className="h-8 w-8 text-blue-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Threat Indicators</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.total_indicators}</p>
                  </div>
                  <ExclamationTriangleIcon className="h-8 w-8 text-orange-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Detection Rules</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.detection_rules}</p>
                  </div>
                  <CpuChipIcon className="h-8 w-8 text-green-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Anomalies Detected</p>
                    <p className="text-2xl font-bold text-gray-900">{metrics.anomalies_detected}</p>
                  </div>
                  <BoltIcon className="h-8 w-8 text-purple-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Avg Confidence</p>
                    <p className="text-2xl font-bold text-gray-900">{(metrics.avg_hunt_confidence * 100).toFixed(1)}%</p>
                  </div>
                  <ChartBarIcon className="h-8 w-8 text-indigo-600" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">System Health</p>
                    <p className="text-2xl font-bold text-gray-900">{(metrics.system_health * 100).toFixed(1)}%</p>
                  </div>
                  <FireIcon className="h-8 w-8 text-red-600" />
                </div>
              </div>
            </div>
          )}

          {/* Recent Events */}
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h3 className="text-lg font-semibold text-gray-900">Recent Security Events</h3>
            </div>
            <div className="p-6">
              {events.length === 0 ? (
                <p className="text-gray-500 text-center py-8">No recent events processed</p>
              ) : (
                <div className="space-y-3">
                  {events.slice(0, 5).map((event) => (
                    <div key={event.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 rounded-full ${event.status === 'success' ? 'bg-green-100' : 'bg-red-100'}`}>
                          <BoltIcon className={`h-4 w-4 ${event.status === 'success' ? 'text-green-600' : 'text-red-600'}`} />
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">{event.type}</p>
                          <p className="text-sm text-gray-600">
                            {event.user && `User: ${event.user}`}
                            {event.source_ip && ` | IP: ${event.source_ip}`}
                          </p>
                        </div>
                      </div>
                      <div className="text-sm text-gray-500">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Active Hunts Tab */}
      {activeTab === 'hunts' && (
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-6 border-b">
            <h3 className="text-lg font-semibold text-gray-900">Active Threat Hunts</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hunt</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Category</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Confidence</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Priority</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Indicators</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {hunts.map((hunt) => (
                  <tr key={hunt.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{hunt.name}</div>
                        <div className="text-sm text-gray-500">ID: {hunt.id}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        {hunt.category}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(hunt.status)}
                        <span className="ml-2 text-sm text-gray-900">{hunt.status}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-full bg-gray-200 rounded-full h-2 mr-2">
                          <div
                            className="bg-blue-600 h-2 rounded-full"
                            style={{ width: `${hunt.confidence * 100}%` }}
                          ></div>
                        </div>
                        <span className="text-sm text-gray-900">{(hunt.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        hunt.priority >= 4 ? 'bg-red-100 text-red-800' : 
                        hunt.priority >= 3 ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'
                      }`}>
                        Priority {hunt.priority}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {hunt.indicators_count}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => updateHuntStatus(hunt.id, 'INVESTIGATING')}
                          className="text-blue-600 hover:text-blue-900"
                        >
                          Investigate
                        </button>
                        <button
                          onClick={() => updateHuntStatus(hunt.id, 'COMPLETED')}
                          className="text-green-600 hover:text-green-900"
                        >
                          Complete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Threat Indicators Tab */}
      {activeTab === 'indicators' && (
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-6 border-b">
            <h3 className="text-lg font-semibold text-gray-900">Threat Indicators</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Indicator</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Confidence</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Occurrences</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Seen</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {indicators.slice(0, 20).map((indicator) => (
                  <tr key={indicator.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{indicator.value}</div>
                        <div className="text-sm text-gray-500">ID: {indicator.id}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                        {indicator.type}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(indicator.severity)}`}>
                        {indicator.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-full bg-gray-200 rounded-full h-2 mr-2">
                          <div
                            className="bg-red-600 h-2 rounded-full"
                            style={{ width: `${indicator.confidence * 100}%` }}
                          ></div>
                        </div>
                        <span className="text-sm text-gray-900">{(indicator.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {indicator.occurrences}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(indicator.last_seen).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Attack Simulation Tab */}
      {activeTab === 'simulate' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Attack Simulation</h3>
            <p className="text-gray-600 mb-6">Test your threat detection capabilities with simulated attack scenarios</p>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { type: 'LATERAL_MOVEMENT', label: 'Lateral Movement', color: 'bg-blue-600' },
                { type: 'DATA_EXFILTRATION', label: 'Data Exfiltration', color: 'bg-red-600' },
                { type: 'INSIDER_THREAT', label: 'Insider Threat', color: 'bg-purple-600' }
              ].map((attack) => (
                <div key={attack.type} className="border rounded-lg p-4">
                  <h4 className="font-medium text-gray-900 mb-2">{attack.label}</h4>
                  <div className="space-y-3">
                    {['low', 'medium', 'high'].map((intensity) => (
                      <button
                        key={intensity}
                        onClick={() => simulateAttack(attack.type, intensity as any, 5)}
                        disabled={isSimulating}
                        className={`w-full ${attack.color} text-white px-4 py-2 rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50`}
                      >
                        {isSimulating ? 'Running...' : `${intensity.charAt(0).toUpperCase() + intensity.slice(1)} Intensity`}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Simulation Results */}
          {simulation && (
            <div className="bg-white rounded-lg shadow-sm border p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Simulation Results</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">{simulation.events_generated}</div>
                  <div className="text-sm text-gray-600">Events Generated</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">{simulation.threats_detected}</div>
                  <div className="text-sm text-gray-600">Threats Detected</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">{(simulation.detection_rate * 100).toFixed(1)}%</div>
                  <div className="text-sm text-gray-600">Detection Rate</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-600">{simulation.attack_type}</div>
                  <div className="text-sm text-gray-600">Attack Type</div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ThreatHunting;