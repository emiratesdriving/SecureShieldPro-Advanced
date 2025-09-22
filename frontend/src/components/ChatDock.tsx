'use client';

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { 
  ChatBubbleLeftIcon, 
  XMarkIcon, 
  PaperAirplaneIcon,
  SparklesIcon,
  ShieldCheckIcon,
  CogIcon,
  DocumentTextIcon,
  LightBulbIcon,
  BeakerIcon,
  EyeIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';

interface Message {
  id: string;
  text: string;
  isUser: boolean;
  timestamp: Date;
  type?: 'info' | 'warning' | 'success' | 'error';
  suggestions?: string[];
  remediation?: {
    available: boolean;
    actions: Array<{
      title: string;
      description: string;
      type: string;
    }>;
  };
}

interface AICapability {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<any>;
  enabled: boolean;
}

const ChatDock = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'chat' | 'remediation' | 'ocr' | 'analysis'>('chat');
  const [aiCapabilities, setAiCapabilities] = useState<AICapability[]>([
    { id: 'chat', name: 'AI Chat', description: 'Intelligent security assistance', icon: ChatBubbleLeftIcon, enabled: true },
    { id: 'remediation', name: 'Auto Remediation', description: 'Automated vulnerability fixing', icon: ShieldCheckIcon, enabled: true },
    { id: 'ocr', name: 'OCR Analysis', description: 'Document text extraction', icon: DocumentTextIcon, enabled: true },
    { id: 'analysis', name: 'Smart Analysis', description: 'Advanced threat detection', icon: BeakerIcon, enabled: true }
  ]);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    // Initialize with a welcome message
    if (messages.length === 0) {
      setMessages([{
        id: '1',
        text: 'Hi! I\'m your AI Security Assistant. I can help with vulnerability analysis, auto-remediation, OCR document processing, and intelligent threat detection. How can I assist you today?',
        isUser: false,
        timestamp: new Date(),
        type: 'info',
        suggestions: ['Analyze my code for vulnerabilities', 'Show me remediation options', 'Help with OCR document scan', 'Explain security best practices']
      }]);
    }
  }, [isOpen]);

  const sendMessage = async () => {
    if (!inputText.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      text: inputText,
      isUser: true,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputText('');
    setIsLoading(true);

    try {
      // Get the auth token
      const token = localStorage.getItem('token');
      
      // Call the enhanced AI chat API
      const response = await fetch('http://localhost:8000/api/v1/ai/chat/message', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': token ? `Bearer ${token}` : ''
        },
        body: JSON.stringify({
          message: inputText,
          context: {
            tab: activeTab,
            capabilities: aiCapabilities.filter(c => c.enabled).map(c => c.id)
          }
        })
      });

      const data = await response.json();
      
      const aiMessage: Message = {
        id: (Date.now() + 1).toString(),
        text: data.message || 'I apologize, but I encountered an issue processing your request. Please try again.',
        isUser: false,
        timestamp: new Date(),
        type: data.type || 'info',
        suggestions: data.suggestions || [],
        remediation: data.remediation
      };

      setMessages(prev => [...prev, aiMessage]);
    } catch (error) {
      console.error('Chat error:', error);
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        text: 'I\'m experiencing connectivity issues. Please check that the backend is running and try again.',
        isUser: false,
        timestamp: new Date(),
        type: 'error'
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const executeRemediation = async (action: any) => {
    setIsLoading(true);
    try {
      // Get the auth token
      const token = localStorage.getItem('token');
      
      const response = await fetch('http://localhost:8000/api/v1/ai-remediation/execute', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': token ? `Bearer ${token}` : ''
        },
        body: JSON.stringify({ action })
      });
      
      const result = await response.json();
      
      const resultMessage: Message = {
        id: Date.now().toString(),
        text: result.success 
          ? `✅ Remediation successful: ${result.message}`
          : `❌ Remediation failed: ${result.message}`,
        isUser: false,
        timestamp: new Date(),
        type: result.success ? 'success' : 'error'
      };
      
      setMessages(prev => [...prev, resultMessage]);
    } catch (error) {
      console.error('Remediation error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('analysis_type', activeTab);

      const response = await fetch('/api/v1/analysis/upload', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();
      
      const uploadMessage: Message = {
        id: Date.now().toString(),
        text: `📄 File "${file.name}" uploaded successfully. Analysis ID: ${result.analysis_id}`,
        isUser: false,
        timestamp: new Date(),
        type: 'success'
      };
      
      setMessages(prev => [...prev, uploadMessage]);
    } catch (error) {
      console.error('Upload error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) {
    return (
      <div className="fixed bottom-6 right-6 z-50">
        <button
          onClick={() => setIsOpen(true)}
          className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-full p-4 shadow-lg transition-all duration-300 hover:scale-110"
        >
          <div className="relative">
            <ChatBubbleLeftIcon className="h-6 w-6" />
            <SparklesIcon className="h-3 w-3 absolute -top-1 -right-1 text-yellow-300" />
          </div>
        </button>
      </div>
    );
  }

  return (
    <div className="fixed bottom-6 right-6 z-50">
      <div className="bg-white/10 backdrop-blur-xl rounded-2xl shadow-2xl border border-white/20 w-96 h-[600px] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-t-2xl">
          <div className="flex items-center space-x-2">
            <SparklesIcon className="h-5 w-5" />
            <span className="font-semibold">AI Security Assistant</span>
          </div>
          <button 
            onClick={() => setIsOpen(false)}
            className="hover:bg-white/20 rounded-lg p-1 transition-colors"
          >
            <XMarkIcon className="h-4 w-4" />
          </button>
        </div>

        {/* Capability Tabs */}
        <div className="flex border-b border-white/10 bg-white/5">
          {aiCapabilities.map((capability) => (
            <button
              key={capability.id}
              onClick={() => setActiveTab(capability.id as any)}
              className={`flex-1 p-2 text-xs font-medium transition-colors ${
                activeTab === capability.id 
                  ? 'text-blue-400 border-b-2 border-blue-400 bg-white/10' 
                  : 'text-gray-300 hover:text-white hover:bg-white/5'
              }`}
            >
              <capability.icon className="h-4 w-4 mx-auto mb-1" />
              <div className="hidden sm:block">{capability.name}</div>
            </button>
          ))}
        </div>

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((message) => (
            <div
              key={message.id}
              className={`flex ${message.isUser ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[80%] rounded-2xl p-3 ${
                  message.isUser
                    ? 'bg-gradient-to-r from-blue-500 to-purple-500 text-white'
                    : 'bg-white/10 text-white border border-white/20'
                } ${
                  message.type === 'error' ? 'border-red-500/50 bg-red-500/10' :
                  message.type === 'success' ? 'border-green-500/50 bg-green-500/10' :
                  message.type === 'warning' ? 'border-yellow-500/50 bg-yellow-500/10' : ''
                }`}
              >
                <p className="text-sm whitespace-pre-wrap">{message.text}</p>
                
                {/* Suggestions */}
                {message.suggestions && message.suggestions.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {message.suggestions.map((suggestion, idx) => (
                      <button
                        key={idx}
                        onClick={() => setInputText(suggestion)}
                        className="block w-full text-left text-xs bg-white/10 hover:bg-white/20 rounded-lg p-2 transition-colors"
                      >
                        💡 {suggestion}
                      </button>
                    ))}
                  </div>
                )}

                {/* Remediation Actions */}
                {message.remediation?.available && (
                  <div className="mt-2 space-y-1">
                    <p className="text-xs font-medium text-green-300">🔧 Auto-Remediation Available:</p>
                    {message.remediation.actions.map((action, idx) => (
                      <button
                        key={idx}
                        onClick={() => executeRemediation(action)}
                        className="block w-full text-left text-xs bg-green-500/20 hover:bg-green-500/30 rounded-lg p-2 transition-colors border border-green-500/30"
                      >
                        <div className="font-medium">{action.title}</div>
                        <div className="text-gray-300">{action.description}</div>
                      </button>
                    ))}
                  </div>
                )}

                <div className="text-xs text-gray-400 mt-2">
                  {message.timestamp.toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}
          
          {isLoading && (
            <div className="flex justify-start">
              <div className="bg-white/10 rounded-2xl p-3 border border-white/20">
                <div className="flex space-x-1">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                </div>
              </div>
            </div>
          )}
          
          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 border-t border-white/10">
          <div className="flex space-x-2">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              className="hidden"
              accept=".txt,.pdf,.doc,.docx,.js,.py,.json,.xml,.html"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg p-2 transition-colors"
              title="Upload file for analysis"
            >
              <DocumentTextIcon className="h-4 w-4 text-white" />
            </button>
            <input
              type="text"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder={`Ask me about ${activeTab}...`}
              className="flex-1 bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white placeholder-gray-300 focus:outline-none focus:border-blue-400 focus:bg-white/20 transition-colors"
            />
            <button
              onClick={sendMessage}
              disabled={!inputText.trim() || isLoading}
              className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg p-2 transition-colors"
            >
              {isLoading ? (
                <ArrowPathIcon className="h-4 w-4 text-white animate-spin" />
              ) : (
                <PaperAirplaneIcon className="h-4 w-4 text-white" />
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ChatDock;
