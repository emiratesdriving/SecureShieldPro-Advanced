'use client';

import React, { useState, useEffect } from 'react';
import {
  GlobeAltIcon,
  UserIcon,
  DocumentTextIcon,
  MagnifyingGlassIcon,
  FlagIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  ChartBarIcon,
  MapIcon,
  ClockIcon,
  TagIcon,
  LinkIcon,
  BeakerIcon,
  PlusIcon,
  EyeIcon,
  FireIcon,
  ShieldCheckIcon,
  BugAntIcon
} from '@heroicons/react/24/outline';

interface IOC {
  id: string;
  type: string;
  value: string;
  threat_level: string;
  confidence: string;
  description: string;
  source: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  related_campaigns: string[];
  related_actors: string[];
  attributes: Record<string, any>;
  is_active: boolean;
  false_positive: boolean;
}

interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  country?: string;
  motivation: string[];
  sophistication: string;
  targets: string[];
  ttps: string[];
  associated_iocs: string[];
  campaigns: string[];
  first_observed: string;
  last_activity: string;
  is_active: boolean;
}

interface ThreatLandscape {
  overview: {
    total_iocs: number;
    active_iocs: number;
    active_threat_actors: number;
    active_campaigns: number;
  };
  threat_levels: Record<string, number>;
  ioc_types: Record<string, number>;
  recent_activity: {
    new_iocs_24h: number;
    updated_iocs_24h: number;
  };
}

interface IOCAnalysis {
  ioc_value: string;
  analysis_time: string;
  threat_level: string;
  confidence: string;
  malicious: boolean;
  sources: string[];
  attributes: Record<string, any>;
  type?: string;
  validation?: string;
  related_actors?: string[];
  related_campaigns?: string[];
}

export default function ThreatIntelligencePage() {
  const [iocs, setIOCs] = useState<IOC[]>([]);
  const [threatActors, setThreatActors] = useState<ThreatActor[]>([]);
  const [landscape, setLandscape] = useState<ThreatLandscape | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'iocs' | 'actors' | 'analysis'>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [analysisValue, setAnalysisValue] = useState('');
  const [analysisResult, setAnalysisResult] = useState<IOCAnalysis | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  const fetchThreatLandscape = async () => {
    try {
      const response = await fetch('/api/v1/threat-intelligence/overview');
      if (response.ok) {
        const data = await response.json();
        setLandscape(data.data);
      }
    } catch (err) {
      setError('Failed to fetch threat landscape');
    }
  };

  const fetchIOCs = async () => {
    try {
      const response = await fetch('/api/v1/threat-intelligence/iocs?limit=50');
      if (response.ok) {
        const data = await response.json();
        setIOCs(data.data.iocs || []);
      }
    } catch (err) {
      setError('Failed to fetch IOCs');
    }
  };

  const fetchThreatActors = async () => {
    try {
      const response = await fetch('/api/v1/threat-intelligence/actors?limit=20');
      if (response.ok) {
        const data = await response.json();
        setThreatActors(data.data.threat_actors || []);
      }
    } catch (err) {
      setError('Failed to fetch threat actors');
    }
  };

  const analyzeIOC = async () => {
    if (!analysisValue.trim()) return;
    
    setAnalyzing(true);
    try {
      const response = await fetch('/api/v1/threat-intelligence/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ioc_value: analysisValue.trim() })
      });
      
      if (response.ok) {
        const data = await response.json();
        setAnalysisResult(data.data);
      }
    } catch (err) {
      console.error('Failed to analyze IOC:', err);
    }
    setAnalyzing(false);
  };

  const searchThreatIntel = async () => {
    if (!searchQuery.trim()) {
      fetchIOCs();
      return;
    }
    
    try {
      const response = await fetch(`/api/v1/threat-intelligence/search?query=${encodeURIComponent(searchQuery)}&search_type=all&limit=50`);
      if (response.ok) {
        const data = await response.json();
        setIOCs(data.data.results.iocs || []);
        setThreatActors(data.data.results.actors || []);
      }
    } catch (err) {
      console.error('Failed to search threat intelligence:', err);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      await Promise.all([fetchThreatLandscape(), fetchIOCs(), fetchThreatActors()]);
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

  const getConfidenceColor = (confidence: string) => {
    switch (confidence.toLowerCase()) {
      case 'high': return 'text-green-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getSophisticationColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'expert': return 'text-red-400 bg-red-400/10';
      case 'advanced': return 'text-orange-400 bg-orange-400/10';
      case 'intermediate': return 'text-yellow-400 bg-yellow-400/10';
      case 'basic': return 'text-blue-400 bg-blue-400/10';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-black p-6">
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
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-black p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                <GlobeAltIcon className="h-8 w-8 text-cyan-400" />
                Threat Intelligence Platform
              </h1>
              <p className="text-gray-300 mt-2">
                Advanced threat intelligence, IOC management, and actor profiling
              </p>
            </div>
            <div className="flex gap-3">
              <div className="relative">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && searchThreatIntel()}
                  placeholder="Search IOCs, actors, campaigns..."
                  className="bg-white/10 border border-white/20 rounded-lg px-4 py-2 pl-10 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-400"
                />
                <MagnifyingGlassIcon className="h-5 w-5 text-gray-400 absolute left-3 top-2.5" />
              </div>
              <button
                onClick={searchThreatIntel}
                className="bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition-colors"
              >
                Search
              </button>
            </div>
          </div>
        </div>

        {/* Overview Cards */}
        {landscape && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Total IOCs</p>
                  <p className="text-2xl font-bold text-white">{landscape.overview.total_iocs}</p>
                </div>
                <BugAntIcon className="h-8 w-8 text-red-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Threat Actors</p>
                  <p className="text-2xl font-bold text-white">{landscape.overview.active_threat_actors}</p>
                </div>
                <UserIcon className="h-8 w-8 text-orange-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">Active Campaigns</p>
                  <p className="text-2xl font-bold text-white">{landscape.overview.active_campaigns}</p>
                </div>
                <DocumentTextIcon className="h-8 w-8 text-yellow-400" />
              </div>
            </div>

            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-white/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-300">New IOCs (24h)</p>
                  <p className="text-2xl font-bold text-cyan-400">{landscape.recent_activity.new_iocs_24h}</p>
                </div>
                <ClockIcon className="h-8 w-8 text-cyan-400" />
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="bg-white/10 backdrop-blur-sm rounded-lg border border-white/20">
          <div className="border-b border-white/20">
            <nav className="flex space-x-8 px-6">
              {['overview', 'iocs', 'actors', 'analysis'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab as any)}
                  className={`py-4 px-1 border-b-2 font-medium text-sm capitalize ${
                    activeTab === tab
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-gray-300 hover:text-white hover:border-gray-300'
                  }`}
                >
                  {tab === 'iocs' ? 'IOCs' : tab}
                </button>
              ))}
            </nav>
          </div>

          {/* Overview Tab */}
          {activeTab === 'overview' && landscape && (
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Threat Levels Chart */}
                <div className="bg-white/5 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <ChartBarIcon className="h-5 w-5 text-cyan-400" />
                    Threat Levels Distribution
                  </h3>
                  <div className="space-y-3">
                    {Object.entries(landscape.threat_levels).map(([level, count]) => (
                      <div key={level} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getThreatLevelColor(level)}`}>
                            {level.toUpperCase()}
                          </span>
                        </div>
                        <span className="text-white font-medium">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* IOC Types Chart */}
                <div className="bg-white/5 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <TagIcon className="h-5 w-5 text-cyan-400" />
                    IOC Types Distribution
                  </h3>
                  <div className="space-y-3">
                    {Object.entries(landscape.ioc_types).map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between">
                        <span className="text-gray-300 capitalize">{type.replace('_', ' ')}</span>
                        <span className="text-white font-medium">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* IOCs Tab */}
          {activeTab === 'iocs' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      IOC
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Threat Level
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Confidence
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Source
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Tags
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {iocs.map((ioc) => (
                    <tr key={ioc.id} className="hover:bg-white/5 transition-colors">
                      <td className="px-6 py-4">
                        <div>
                          <p className="text-sm font-medium text-white break-all">{ioc.value}</p>
                          <p className="text-xs text-gray-400">{ioc.description}</p>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-gray-300 capitalize">
                          {ioc.type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getThreatLevelColor(ioc.threat_level)}`}>
                          {ioc.threat_level.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`text-sm font-medium ${getConfidenceColor(ioc.confidence)}`}>
                          {ioc.confidence.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {ioc.source}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-wrap gap-1">
                          {ioc.tags.slice(0, 3).map((tag, index) => (
                            <span key={index} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/10 text-cyan-400">
                              {tag}
                            </span>
                          ))}
                          {ioc.tags.length > 3 && (
                            <span className="text-xs text-gray-400">+{ioc.tags.length - 3} more</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {iocs.length === 0 && (
                <div className="text-center py-12">
                  <BugAntIcon className="mx-auto h-12 w-12 text-gray-400" />
                  <h3 className="mt-2 text-sm font-medium text-gray-300">No IOCs found</h3>
                  <p className="mt-1 text-sm text-gray-400">Try adjusting your search query.</p>
                </div>
              )}
            </div>
          )}

          {/* Threat Actors Tab */}
          {activeTab === 'actors' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Actor
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Country
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Sophistication
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Motivation
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Targets
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      IOCs
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {threatActors.map((actor) => (
                    <tr key={actor.id} className="hover:bg-white/5 transition-colors">
                      <td className="px-6 py-4">
                        <div>
                          <p className="text-sm font-medium text-white">{actor.name}</p>
                          <p className="text-xs text-gray-400">{actor.aliases.join(', ')}</p>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-1">
                          <FlagIcon className="h-4 w-4 text-gray-400" />
                          <span className="text-sm text-gray-300">{actor.country || 'Unknown'}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSophisticationColor(actor.sophistication)}`}>
                          {actor.sophistication.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-wrap gap-1">
                          {actor.motivation.slice(0, 2).map((motive, index) => (
                            <span key={index} className="text-xs text-gray-300 capitalize">
                              {motive.replace('_', ' ')}
                              {index < Math.min(actor.motivation.length, 2) - 1 && ', '}
                            </span>
                          ))}
                          {actor.motivation.length > 2 && (
                            <span className="text-xs text-gray-400">+{actor.motivation.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-wrap gap-1">
                          {actor.targets.slice(0, 2).map((target, index) => (
                            <span key={index} className="text-xs text-gray-300 capitalize">
                              {target.replace('_', ' ')}
                              {index < Math.min(actor.targets.length, 2) - 1 && ', '}
                            </span>
                          ))}
                          {actor.targets.length > 2 && (
                            <span className="text-xs text-gray-400">+{actor.targets.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        {actor.associated_iocs.length} IOCs
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {threatActors.length === 0 && (
                <div className="text-center py-12">
                  <UserIcon className="mx-auto h-12 w-12 text-gray-400" />
                  <h3 className="mt-2 text-sm font-medium text-gray-300">No threat actors found</h3>
                  <p className="mt-1 text-sm text-gray-400">Try adjusting your search query.</p>
                </div>
              )}
            </div>
          )}

          {/* IOC Analysis Tab */}
          {activeTab === 'analysis' && (
            <div className="p-6">
              <div className="max-w-2xl mx-auto">
                <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                  <BeakerIcon className="h-5 w-5 text-cyan-400" />
                  IOC Analysis
                </h3>
                
                <div className="bg-white/5 rounded-lg p-6">
                  <div className="flex gap-3 mb-6">
                    <input
                      type="text"
                      value={analysisValue}
                      onChange={(e) => setAnalysisValue(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && analyzeIOC()}
                      placeholder="Enter IP, domain, hash, or URL to analyze..."
                      className="flex-1 bg-white/10 border border-white/20 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-400"
                    />
                    <button
                      onClick={analyzeIOC}
                      disabled={analyzing || !analysisValue.trim()}
                      className="bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white px-6 py-3 rounded-lg transition-colors flex items-center gap-2"
                    >
                      {analyzing ? (
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                      ) : (
                        <MagnifyingGlassIcon className="h-4 w-4" />
                      )}
                      Analyze
                    </button>
                  </div>

                  {analysisResult && (
                    <div className="space-y-4">
                      <div className="border-t border-white/20 pt-4">
                        <h4 className="text-white font-medium mb-3">Analysis Results</h4>
                        
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="bg-white/5 rounded-lg p-4">
                            <p className="text-sm text-gray-300 mb-1">IOC Value</p>
                            <p className="text-white font-mono break-all">{analysisResult.ioc_value}</p>
                          </div>
                          
                          <div className="bg-white/5 rounded-lg p-4">
                            <p className="text-sm text-gray-300 mb-1">Type</p>
                            <p className="text-white capitalize">{analysisResult.type?.replace('_', ' ') || 'Unknown'}</p>
                          </div>
                          
                          <div className="bg-white/5 rounded-lg p-4">
                            <p className="text-sm text-gray-300 mb-1">Threat Level</p>
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getThreatLevelColor(analysisResult.threat_level)}`}>
                              {analysisResult.threat_level.toUpperCase()}
                            </span>
                          </div>
                          
                          <div className="bg-white/5 rounded-lg p-4">
                            <p className="text-sm text-gray-300 mb-1">Malicious</p>
                            <div className="flex items-center gap-2">
                              {analysisResult.malicious ? (
                                <ExclamationTriangleIcon className="h-5 w-5 text-red-400" />
                              ) : (
                                <ShieldCheckIcon className="h-5 w-5 text-green-400" />
                              )}
                              <span className={analysisResult.malicious ? 'text-red-400' : 'text-green-400'}>
                                {analysisResult.malicious ? 'Yes' : 'No'}
                              </span>
                            </div>
                          </div>
                        </div>

                        {analysisResult.attributes && Object.keys(analysisResult.attributes).length > 0 && (
                          <div className="mt-4 bg-white/5 rounded-lg p-4">
                            <p className="text-sm text-gray-300 mb-2">Additional Attributes</p>
                            <div className="text-sm text-gray-400 font-mono">
                              {JSON.stringify(analysisResult.attributes, null, 2)}
                            </div>
                          </div>
                        )}

                        {analysisResult.related_actors && analysisResult.related_actors.length > 0 && (
                          <div className="mt-4 bg-white/5 rounded-lg p-4">
                            <p className="text-sm text-gray-300 mb-2">Related Threat Actors</p>
                            <div className="flex flex-wrap gap-2">
                              {analysisResult.related_actors.map((actor, index) => (
                                <span key={index} className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-orange-500/10 text-orange-400">
                                  {actor}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}