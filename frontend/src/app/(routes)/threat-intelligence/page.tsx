'use client';

import React, { useState, useEffect } from 'react';
import {
  BugAntIcon,
  ShieldExclamationIcon,
  UserGroupIcon,
  GlobeAltIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  CalendarIcon,
  TagIcon,
  ArrowPathIcon,
  PlusIcon,
  EyeIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  ChartBarIcon,
  FireIcon,
  BeakerIcon
} from '@heroicons/react/24/outline';

interface IOC {
  ioc_id: string;
  type: string;
  value: string;
  description?: string;
  threat_level: string;
  confidence: number;
  source?: string;
  tags?: string[];
  first_seen?: string;
  last_seen?: string;
  detection_count: number;
  is_active: boolean;
  threat_actor?: string;
  campaign?: string;
  created_at: string;
}

interface ThreatActor {
  actor_id: string;
  name: string;
  aliases?: string[];
  actor_type: string;
  sophistication?: string;
  country?: string;
  motivation?: string[];
  is_active: boolean;
  first_seen?: string;
  last_seen?: string;
  ioc_count: number;
  campaign_count: number;
  created_at: string;
}

interface ThreatIntelSummary {
  iocs: {
    total: number;
    active: number;
    by_type: Record<string, number>;
    by_threat_level: Record<string, number>;
  };
  detections: {
    last_24h: number;
  };
  threat_actors: {
    total: number;
    active: number;
  };
  campaigns: {
    total: number;
    active: number;
  };
}

export default function ThreatIntelligencePage() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [threatActors, setThreatActors] = useState<ThreatActor[]>([]);
  const [summary, setSummary] = useState<ThreatIntelSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'iocs' | 'actors' | 'analytics'>('iocs');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFilter, setSelectedFilter] = useState<string>('all');

  const fetchIOCs = async () => {
    try {
      const response = await fetch('/api/v1/threat-intelligence/iocs?limit=100');
      if (response.ok) {
        const data = await response.json();
        setIocs(data.iocs || []);
      }
    } catch (err) {
      setError('Failed to fetch IOCs');
    }
  };

  const fetchThreatActors = async () => {
    try {
      const response = await fetch('/api/v1/threat-intelligence/threat-actors?limit=50');
      if (response.ok) {
        const data = await response.json();
        setThreatActors(data.threat_actors || []);
      }
    } catch (err) {
      setError('Failed to fetch threat actors');
    }
  };

  const fetchSummary = async () => {
    try {
      const response = await fetch('/api/v1/threat-intelligence/analytics/summary');
      if (response.ok) {
        const data = await response.json();
        setSummary(data);
      }
    } catch (err) {
      setError('Failed to fetch summary');
    }
  };

  const createSampleIOC = async (iocType: string) => {
    const sampleIOCs = {
      ip: {
        type: 'ip',
        value: '192.168.100.' + Math.floor(Math.random() * 255),
        description: 'Suspicious IP address detected in network traffic',
        threat_level: 'high',
        confidence: 85,
        source: 'internal_detection',
        tags: ['malware', 'botnet', 'suspicious_activity']
      },
      domain: {
        type: 'domain',
        value: `malicious-${Math.floor(Math.random() * 1000)}.evil.com`,
        description: 'Known malicious domain hosting malware',
        threat_level: 'critical',
        confidence: 90,
        source: 'threat_feed',
        tags: ['malware', 'c2', 'phishing']
      },
      file_hash: {
        type: 'file_hash',
        value: 'a1b2c3d4e5f6' + Array(20).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join(''),
        description: 'SHA256 hash of malicious executable',
        threat_level: 'high',
        confidence: 95,
        source: 'av_detection',
        tags: ['malware', 'trojan', 'executable']
      }
    };

    try {
      const response = await fetch('/api/v1/threat-intelligence/iocs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sampleIOCs[iocType as keyof typeof sampleIOCs])
      });
      
      if (response.ok) {
        await fetchIOCs();
        await fetchSummary();
      }
    } catch (err) {
      console.error('Failed to create sample IOC:', err);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      await Promise.all([fetchIOCs(), fetchThreatActors(), fetchSummary()]);
      setLoading(false);
    };
    loadData();
  }, []);

  const getThreatLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
      case 'info': return 'text-gray-500 bg-gray-500/10 border-gray-500/20';
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500/20';
    }
  };

  const getIOCTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ip': return <GlobeAltIcon className="h-4 w-4" />;
      case 'domain': return <GlobeAltIcon className="h-4 w-4" />;
      case 'file_hash': return <BugAntIcon className="h-4 w-4" />;
      case 'url': return <GlobeAltIcon className="h-4 w-4" />;
      case 'email': return <UserGroupIcon className="h-4 w-4" />;
      default: return <ShieldExclamationIcon className="h-4 w-4" />;
    }
  };

  const filteredIOCs = iocs.filter(ioc => {
    const matchesSearch = !searchQuery || 
      ioc.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ioc.description?.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesFilter = selectedFilter === 'all' || 
      ioc.type === selectedFilter || 
      ioc.threat_level === selectedFilter;
    
    return matchesSearch && matchesFilter;
  });

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-indigo-900 to-purple-900 p-6">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-white/10 rounded-lg w-1/3"></div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-24 bg-white/10 rounded-lg"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-indigo-900 to-purple-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                <BugAntIcon className="h-8 w-8 text-indigo-400" />
                Threat Intelligence Platform
              </h1>
              <p className="text-gray-300 mt-2">
                Advanced threat intelligence with IOC management and threat actor profiling
              </p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => createSampleIOC('ip')}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
              >
                <BeakerIcon className="h-5 w-5" />
                Add IP IOC
              </button>
              <button
                onClick={() => createSampleIOC('domain')}
                className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
              >
                <FireIcon className="h-5 w-5" />
                Add Domain IOC
              </button>
            </div>
          </div>
        </div>

        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Total IOCs</p>
                  <p className="text-2xl font-bold text-white">{summary.iocs.total}</p>
                  <p className="text-xs text-green-400">{summary.iocs.active} active</p>
                </div>
                <BugAntIcon className="h-8 w-8 text-indigo-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Recent Detections</p>
                  <p className="text-2xl font-bold text-orange-400">{summary.detections.last_24h}</p>
                  <p className="text-xs text-gray-400">Last 24 hours</p>
                </div>
                <ExclamationTriangleIcon className="h-8 w-8 text-orange-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Threat Actors</p>
                  <p className="text-2xl font-bold text-red-400">{summary.threat_actors.total}</p>
                  <p className="text-xs text-green-400">{summary.threat_actors.active} active</p>
                </div>
                <UserGroupIcon className="h-8 w-8 text-red-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Active Campaigns</p>
                  <p className="text-2xl font-bold text-purple-400">{summary.campaigns.active}</p>
                  <p className="text-xs text-gray-400">{summary.campaigns.total} total</p>
                </div>
                <ChartBarIcon className="h-8 w-8 text-purple-400" />
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20">
          <div className="border-b border-white/20">
            <nav className="flex space-x-8 px-6">
              <button
                onClick={() => setActiveTab('iocs')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'iocs'
                    ? 'border-indigo-400 text-indigo-400'
                    : 'border-transparent text-gray-300 hover:text-white hover:border-gray-300'
                }`}
              >
                Indicators of Compromise
              </button>
              <button
                onClick={() => setActiveTab('actors')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'actors'
                    ? 'border-indigo-400 text-indigo-400'
                    : 'border-transparent text-gray-300 hover:text-white hover:border-gray-300'
                }`}
              >
                Threat Actors
              </button>
              <button
                onClick={() => setActiveTab('analytics')}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'analytics'
                    ? 'border-indigo-400 text-indigo-400'
                    : 'border-transparent text-gray-300 hover:text-white hover:border-gray-300'
                }`}
              >
                Analytics & Trends
              </button>
            </nav>
          </div>

          {/* IOCs Tab */}
          {activeTab === 'iocs' && (
            <div>
              {/* Search and Filters */}
              <div className="p-6 border-b border-white/20">
                <div className="flex flex-col sm:flex-row gap-4">
                  <div className="flex-1">
                    <div className="relative">
                      <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                      <input
                        type="text"
                        placeholder="Search IOCs..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full pl-10 pr-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                      />
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <select
                      value={selectedFilter}
                      onChange={(e) => setSelectedFilter(e.target.value)}
                      className="px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    >
                      <option value="all">All Types</option>
                      <option value="ip">IP Addresses</option>
                      <option value="domain">Domains</option>
                      <option value="file_hash">File Hashes</option>
                      <option value="url">URLs</option>
                      <option value="email">Emails</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* IOCs Table */}
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Indicator
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Threat Level
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Confidence
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Detections
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Source
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        First Seen
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/10">
                    {filteredIOCs.map((ioc) => (
                      <tr key={ioc.ioc_id} className="hover:bg-white/5 transition-colors">
                        <td className="px-6 py-4">
                          <div className="flex items-start gap-3">
                            <div className="mt-1">
                              {getIOCTypeIcon(ioc.type)}
                            </div>
                            <div>
                              <p className="text-sm font-medium text-white font-mono">{ioc.value}</p>
                              <p className="text-xs text-gray-400 uppercase">{ioc.type}</p>
                              {ioc.description && (
                                <p className="text-xs text-gray-500 mt-1 max-w-xs truncate">
                                  {ioc.description}
                                </p>
                              )}
                              {ioc.tags && ioc.tags.length > 0 && (
                                <div className="flex gap-1 mt-2">
                                  {ioc.tags.slice(0, 3).map((tag, index) => (
                                    <span key={index} className="inline-flex items-center px-2 py-1 rounded text-xs bg-indigo-500/20 text-indigo-300">
                                      <TagIcon className="h-3 w-3 mr-1" />
                                      {tag}
                                    </span>
                                  ))}
                                  {ioc.tags.length > 3 && (
                                    <span className="text-xs text-gray-400">+{ioc.tags.length - 3} more</span>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getThreatLevelColor(ioc.threat_level)}`}>
                            {ioc.threat_level.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center">
                            <div className="flex-1 bg-gray-700 rounded-full h-2 mr-3 w-16">
                              <div 
                                className="bg-indigo-400 h-2 rounded-full"
                                style={{ width: `${ioc.confidence}%` }}
                              ></div>
                            </div>
                            <span className="text-sm text-white">{ioc.confidence}%</span>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-1">
                            <ExclamationTriangleIcon className="h-4 w-4 text-orange-400" />
                            <span className="text-sm text-white">{ioc.detection_count}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-300">
                          {ioc.source || 'Unknown'}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-300">
                          <div className="flex items-center gap-1">
                            <CalendarIcon className="h-4 w-4" />
                            {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : 'Unknown'}
                          </div>
                          <div className="text-xs text-gray-400">
                            {ioc.first_seen ? new Date(ioc.first_seen).toLocaleTimeString() : ''}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {filteredIOCs.length === 0 && (
                  <div className="text-center py-12">
                    <BugAntIcon className="mx-auto h-12 w-12 text-gray-400" />
                    <h3 className="mt-2 text-sm font-medium text-gray-300">No IOCs found</h3>
                    <p className="mt-1 text-sm text-gray-400">Create sample IOCs to populate the threat intelligence database.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Threat Actors Tab */}
          {activeTab === 'actors' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Threat Actor
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Origin
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      IOCs
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Campaigns
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Last Activity
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {threatActors.map((actor) => (
                    <tr key={actor.actor_id} className="hover:bg-white/5 transition-colors">
                      <td className="px-6 py-4">
                        <div>
                          <p className="text-sm font-medium text-white">{actor.name}</p>
                          {actor.aliases && actor.aliases.length > 0 && (
                            <p className="text-xs text-gray-400">
                              Aliases: {actor.aliases.slice(0, 2).join(', ')}
                              {actor.aliases.length > 2 && ` +${actor.aliases.length - 2} more`}
                            </p>
                          )}
                          <div className="flex items-center mt-1">
                            {actor.is_active ? (
                              <CheckCircleIcon className="h-4 w-4 text-green-400 mr-1" />
                            ) : (
                              <XCircleIcon className="h-4 w-4 text-gray-400 mr-1" />
                            )}
                            <span className="text-xs text-gray-400">
                              {actor.is_active ? 'Active' : 'Inactive'}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-300 border border-red-500/30">
                          {actor.actor_type.replace('_', ' ').toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {actor.country || 'Unknown'}
                      </td>
                      <td className="px-6 py-4 text-sm text-white">
                        {actor.ioc_count}
                      </td>
                      <td className="px-6 py-4 text-sm text-white">
                        {actor.campaign_count}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {actor.last_seen ? new Date(actor.last_seen).toLocaleDateString() : 'Unknown'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {threatActors.length === 0 && (
                <div className="text-center py-12">
                  <UserGroupIcon className="mx-auto h-12 w-12 text-gray-400" />
                  <h3 className="mt-2 text-sm font-medium text-gray-300">No threat actors found</h3>
                  <p className="mt-1 text-sm text-gray-400">Threat actor profiles will appear here as they are identified.</p>
                </div>
              )}
            </div>
          )}

          {/* Analytics Tab */}
          {activeTab === 'analytics' && summary && (
            <div className="p-6 space-y-8">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* IOCs by Type */}
                <div className="bg-white/5 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">IOCs by Type</h3>
                  <div className="space-y-3">
                    {Object.entries(summary.iocs.by_type).map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {getIOCTypeIcon(type)}
                          <span className="text-gray-300 capitalize">{type.replace('_', ' ')}</span>
                        </div>
                        <span className="text-white font-medium">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* IOCs by Threat Level */}
                <div className="bg-white/5 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">IOCs by Threat Level</h3>
                  <div className="space-y-3">
                    {Object.entries(summary.iocs.by_threat_level).map(([level, count]) => (
                      <div key={level} className="flex items-center justify-between">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getThreatLevelColor(level)}`}>
                          {level.toUpperCase()}
                        </span>
                        <span className="text-white font-medium">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Recent Activity Summary */}
              <div className="bg-white/5 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Platform Activity Summary</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                  <div>
                    <p className="text-2xl font-bold text-indigo-400">{summary.iocs.total}</p>
                    <p className="text-sm text-gray-400">Total IOCs</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-orange-400">{summary.detections.last_24h}</p>
                    <p className="text-sm text-gray-400">Detections (24h)</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-red-400">{summary.threat_actors.total}</p>
                    <p className="text-sm text-gray-400">Threat Actors</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-purple-400">{summary.campaigns.total}</p>
                    <p className="text-sm text-gray-400">Campaigns</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
