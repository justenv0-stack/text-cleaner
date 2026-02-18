import React, { useState, useCallback } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
  ActivityIndicator,
  Platform,
  KeyboardAvoidingView,
  Alert,
  Clipboard,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import { StatusBar } from 'expo-status-bar';

const API_URL = process.env.EXPO_PUBLIC_BACKEND_URL;

interface Finding {
  type: string;
  description: string;
  count: number;
  severity: string;
  character?: string;
  unicode?: string;
  looks_like?: string;
  matches?: string[];
  hidden_content?: string;
}

interface ScanResult {
  id: string;
  threat_level: string;
  total_findings: number;
  findings: Finding[];
  summary: Record<string, { count: number; severity: string }>;
}

interface CleanResult {
  cleaned_text: string;
  characters_removed: number;
  removed_details: { type: string; count: number }[];
  threat_level_before: string;
}

export default function Index() {
  const [inputText, setInputText] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [cleanResult, setCleanResult] = useState<CleanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'scan' | 'clean' | 'info'>('scan');

  const handleScan = async () => {
    if (!inputText.trim()) {
      Alert.alert('Error', 'Please enter some text to scan');
      return;
    }

    setLoading(true);
    setScanResult(null);
    setCleanResult(null);

    try {
      const response = await fetch(`${API_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText }),
      });

      if (!response.ok) throw new Error('Scan failed');
      const result = await response.json();
      setScanResult(result);
    } catch (error) {
      Alert.alert('Error', 'Failed to scan text. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleClean = async () => {
    if (!inputText.trim()) {
      Alert.alert('Error', 'Please enter some text to clean');
      return;
    }

    setLoading(true);
    setScanResult(null);
    setCleanResult(null);

    try {
      const response = await fetch(`${API_URL}/api/clean`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText }),
      });

      if (!response.ok) throw new Error('Clean failed');
      const result = await response.json();
      setCleanResult(result);
    } catch (error) {
      Alert.alert('Error', 'Failed to clean text. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const copyCleanedText = () => {
    if (cleanResult?.cleaned_text) {
      Clipboard.setString(cleanResult.cleaned_text);
      Alert.alert('Copied!', 'Cleaned text copied to clipboard');
    }
  };

  const useCleanedText = () => {
    if (cleanResult?.cleaned_text) {
      setInputText(cleanResult.cleaned_text);
      setCleanResult(null);
      Alert.alert('Done', 'Cleaned text is now in the input field');
    }
  };

  const clearAll = () => {
    setInputText('');
    setScanResult(null);
    setCleanResult(null);
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'critical': return '#FF3B30';
      case 'high': return '#FF9500';
      case 'medium': return '#FFCC00';
      case 'low': return '#34C759';
      case 'safe': return '#30D158';
      default: return '#8E8E93';
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'critical':
      case 'high': return 'warning';
      case 'medium': return 'alert-circle';
      case 'low':
      case 'safe': return 'checkmark-circle';
      default: return 'help-circle';
    }
  };

  const renderScanResults = () => {
    if (!scanResult) return null;

    return (
      <View style={styles.resultsContainer}>
        <View style={[styles.threatBadge, { backgroundColor: getThreatColor(scanResult.threat_level) }]}>
          <Ionicons name={getThreatIcon(scanResult.threat_level) as any} size={24} color="#FFF" />
          <Text style={styles.threatText}>
            {scanResult.threat_level.toUpperCase()}
          </Text>
        </View>

        <Text style={styles.findingsCount}>
          {scanResult.total_findings} threat{scanResult.total_findings !== 1 ? 's' : ''} detected
        </Text>

        {scanResult.findings.length > 0 && (
          <View style={styles.findingsList}>
            {scanResult.findings.map((finding, index) => (
              <View key={index} style={styles.findingItem}>
                <View style={styles.findingHeader}>
                  <View style={[styles.severityDot, { backgroundColor: getThreatColor(finding.severity) }]} />
                  <Text style={styles.findingType}>
                    {finding.type.replace(/_/g, ' ').toUpperCase()}
                  </Text>
                  <Text style={styles.findingCount}>x{finding.count}</Text>
                </View>
                <Text style={styles.findingDesc}>{finding.description}</Text>
                {finding.unicode && (
                  <Text style={styles.findingDetail}>Unicode: {finding.unicode}</Text>
                )}
                {finding.looks_like && (
                  <Text style={styles.findingDetail}>Looks like: "{finding.looks_like}"</Text>
                )}
                {finding.hidden_content && (
                  <Text style={styles.findingDetail}>Hidden: "{finding.hidden_content}"</Text>
                )}
                {finding.matches && finding.matches.length > 0 && (
                  <Text style={styles.findingDetail}>Found: "{finding.matches[0]}"</Text>
                )}
              </View>
            ))}
          </View>
        )}

        {scanResult.total_findings === 0 && (
          <View style={styles.safeMessage}>
            <Ionicons name="shield-checkmark" size={48} color="#30D158" />
            <Text style={styles.safeText}>Text appears safe!</Text>
            <Text style={styles.safeSubtext}>No prompt injection threats detected</Text>
          </View>
        )}
      </View>
    );
  };

  const renderCleanResults = () => {
    if (!cleanResult) return null;

    return (
      <View style={styles.resultsContainer}>
        <View style={styles.cleanHeader}>
          <Ionicons name="sparkles" size={24} color="#30D158" />
          <Text style={styles.cleanTitle}>Text Cleaned!</Text>
        </View>

        <View style={styles.statsRow}>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>{cleanResult.characters_removed}</Text>
            <Text style={styles.statLabel}>Chars Removed</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>{cleanResult.threat_level_before.toUpperCase()}</Text>
            <Text style={styles.statLabel}>Threat Before</Text>
          </View>
        </View>

        {cleanResult.removed_details.length > 0 && (
          <View style={styles.removedList}>
            <Text style={styles.removedTitle}>Removed:</Text>
            {cleanResult.removed_details.map((item, index) => (
              <Text key={index} style={styles.removedItem}>
                • {item.type.replace(/_/g, ' ')}: {item.count}
              </Text>
            ))}
          </View>
        )}

        <View style={styles.cleanedTextBox}>
          <Text style={styles.cleanedLabel}>Cleaned Text:</Text>
          <ScrollView style={styles.cleanedScroll} nestedScrollEnabled>
            <Text style={styles.cleanedText} selectable>
              {cleanResult.cleaned_text || '(empty after cleaning)'}
            </Text>
          </ScrollView>
        </View>

        <View style={styles.cleanActions}>
          <TouchableOpacity style={styles.cleanActionBtn} onPress={copyCleanedText}>
            <Ionicons name="copy-outline" size={20} color="#007AFF" />
            <Text style={styles.cleanActionText}>Copy</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.cleanActionBtn} onPress={useCleanedText}>
            <Ionicons name="arrow-undo-outline" size={20} color="#007AFF" />
            <Text style={styles.cleanActionText}>Use This</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  };

  const renderInfoTab = () => (
    <ScrollView style={styles.infoContainer}>
      <Text style={styles.infoTitle}>Protection Techniques</Text>
      
      <View style={styles.infoCard}>
        <View style={styles.infoCardHeader}>
          <Ionicons name="eye-off" size={20} color="#FF3B30" />
          <Text style={styles.infoCardTitle}>Zero-Width Characters</Text>
        </View>
        <Text style={styles.infoCardText}>
          Invisible Unicode characters (ZWSP, ZWNJ, ZWJ) used to hide malicious payloads in seemingly normal text.
        </Text>
      </View>

      <View style={styles.infoCard}>
        <View style={styles.infoCardHeader}>
          <Ionicons name="swap-horizontal" size={20} color="#FF9500" />
          <Text style={styles.infoCardTitle}>Bidirectional Overrides</Text>
        </View>
        <Text style={styles.infoCardText}>
          Characters that change text direction (RTL/LTR), used to visually disguise malicious content.
        </Text>
      </View>

      <View style={styles.infoCard}>
        <View style={styles.infoCardHeader}>
          <Ionicons name="text" size={20} color="#FFCC00" />
          <Text style={styles.infoCardTitle}>Homoglyphs</Text>
        </View>
        <Text style={styles.infoCardText}>
          Lookalike characters from Cyrillic/Greek scripts that appear identical to Latin letters but bypass filters.
        </Text>
      </View>

      <View style={styles.infoCard}>
        <View style={styles.infoCardHeader}>
          <Ionicons name="code-slash" size={20} color="#FF3B30" />
          <Text style={styles.infoCardTitle}>ASCII Smuggling</Text>
        </View>
        <Text style={styles.infoCardText}>
          Unicode tag characters (U+E0000-E007F) encoding hidden ASCII messages invisible to humans.
        </Text>
      </View>

      <View style={styles.infoCard}>
        <View style={styles.infoCardHeader}>
          <Ionicons name="alert-circle" size={20} color="#FF9500" />
          <Text style={styles.infoCardTitle}>Instruction Injection</Text>
        </View>
        <Text style={styles.infoCardText}>
          Text patterns like "ignore previous instructions" attempting to override system prompts.
        </Text>
      </View>

      <View style={styles.infoCard}>
        <View style={styles.infoCardHeader}>
          <Ionicons name="lock-closed" size={20} color="#FF9500" />
          <Text style={styles.infoCardTitle}>Base64 Payloads</Text>
        </View>
        <Text style={styles.infoCardText}>
          Encoded content that may contain hidden instructions to manipulate LLM behavior.
        </Text>
      </View>

      <View style={styles.infoCard}>
        <View style={styles.infoCardHeader}>
          <Ionicons name="git-branch" size={20} color="#FFCC00" />
          <Text style={styles.infoCardTitle}>Delimiter Injection</Text>
        </View>
        <Text style={styles.infoCardText}>
          Attempts to break out of prompts using markers like [INST], code blocks, or role delimiters.
        </Text>
      </View>
    </ScrollView>
  );

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      
      <View style={styles.header}>
        <View style={styles.headerContent}>
          <Ionicons name="shield-checkmark" size={28} color="#30D158" />
          <Text style={styles.headerTitle}>LLM Text Guard</Text>
        </View>
        <Text style={styles.headerSubtitle}>Protect against prompt injection</Text>
      </View>

      <View style={styles.tabBar}>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'scan' && styles.activeTab]}
          onPress={() => setActiveTab('scan')}
        >
          <Ionicons name="scan" size={20} color={activeTab === 'scan' ? '#007AFF' : '#8E8E93'} />
          <Text style={[styles.tabText, activeTab === 'scan' && styles.activeTabText]}>Scan</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'clean' && styles.activeTab]}
          onPress={() => setActiveTab('clean')}
        >
          <Ionicons name="sparkles" size={20} color={activeTab === 'clean' ? '#007AFF' : '#8E8E93'} />
          <Text style={[styles.tabText, activeTab === 'clean' && styles.activeTabText]}>Clean</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'info' && styles.activeTab]}
          onPress={() => setActiveTab('info')}
        >
          <Ionicons name="information-circle" size={20} color={activeTab === 'info' ? '#007AFF' : '#8E8E93'} />
          <Text style={[styles.tabText, activeTab === 'info' && styles.activeTabText]}>Info</Text>
        </TouchableOpacity>
      </View>

      <KeyboardAvoidingView
        style={styles.content}
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      >
        {activeTab === 'info' ? (
          renderInfoTab()
        ) : (
          <ScrollView style={styles.scrollContent} keyboardShouldPersistTaps="handled">
            <View style={styles.inputSection}>
              <View style={styles.inputHeader}>
                <Text style={styles.inputLabel}>Enter text to {activeTab}</Text>
                {inputText.length > 0 && (
                  <TouchableOpacity onPress={clearAll}>
                    <Ionicons name="close-circle" size={24} color="#8E8E93" />
                  </TouchableOpacity>
                )}
              </View>
              <TextInput
                style={styles.textInput}
                multiline
                placeholder="Paste or type text here...\n\nThis will detect hidden characters, homoglyphs, and prompt injection attempts."
                placeholderTextColor="#636366"
                value={inputText}
                onChangeText={setInputText}
                textAlignVertical="top"
              />
              <Text style={styles.charCount}>{inputText.length} characters</Text>
            </View>

            <View style={styles.buttonRow}>
              {activeTab === 'scan' ? (
                <TouchableOpacity
                  style={[styles.primaryBtn, loading && styles.disabledBtn]}
                  onPress={handleScan}
                  disabled={loading}
                >
                  {loading ? (
                    <ActivityIndicator color="#FFF" />
                  ) : (
                    <>
                      <Ionicons name="scan" size={20} color="#FFF" />
                      <Text style={styles.primaryBtnText}>Scan for Threats</Text>
                    </>
                  )}
                </TouchableOpacity>
              ) : (
                <TouchableOpacity
                  style={[styles.primaryBtn, styles.cleanBtn, loading && styles.disabledBtn]}
                  onPress={handleClean}
                  disabled={loading}
                >
                  {loading ? (
                    <ActivityIndicator color="#FFF" />
                  ) : (
                    <>
                      <Ionicons name="sparkles" size={20} color="#FFF" />
                      <Text style={styles.primaryBtnText}>Clean Text</Text>
                    </>
                  )}
                </TouchableOpacity>
              )}
            </View>

            {activeTab === 'scan' && renderScanResults()}
            {activeTab === 'clean' && renderCleanResults()}
          </ScrollView>
        )}
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000000',
  },
  header: {
    paddingHorizontal: 20,
    paddingTop: 12,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#1C1C1E',
  },
  headerContent: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: '700',
    color: '#FFFFFF',
  },
  headerSubtitle: {
    fontSize: 14,
    color: '#8E8E93',
    marginTop: 4,
    marginLeft: 38,
  },
  tabBar: {
    flexDirection: 'row',
    backgroundColor: '#1C1C1E',
    marginHorizontal: 16,
    marginTop: 16,
    borderRadius: 12,
    padding: 4,
  },
  tab: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 10,
    borderRadius: 8,
    gap: 6,
  },
  activeTab: {
    backgroundColor: '#2C2C2E',
  },
  tabText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#8E8E93',
  },
  activeTabText: {
    color: '#007AFF',
  },
  content: {
    flex: 1,
  },
  scrollContent: {
    flex: 1,
    padding: 16,
  },
  inputSection: {
    marginBottom: 16,
  },
  inputHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  inputLabel: {
    fontSize: 16,
    fontWeight: '600',
    color: '#FFFFFF',
  },
  textInput: {
    backgroundColor: '#1C1C1E',
    borderRadius: 12,
    padding: 16,
    fontSize: 16,
    color: '#FFFFFF',
    minHeight: 150,
    maxHeight: 200,
    borderWidth: 1,
    borderColor: '#2C2C2E',
  },
  charCount: {
    fontSize: 12,
    color: '#636366',
    textAlign: 'right',
    marginTop: 6,
  },
  buttonRow: {
    marginBottom: 20,
  },
  primaryBtn: {
    backgroundColor: '#007AFF',
    borderRadius: 12,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  cleanBtn: {
    backgroundColor: '#30D158',
  },
  disabledBtn: {
    opacity: 0.6,
  },
  primaryBtnText: {
    fontSize: 17,
    fontWeight: '600',
    color: '#FFFFFF',
  },
  resultsContainer: {
    backgroundColor: '#1C1C1E',
    borderRadius: 16,
    padding: 20,
    marginBottom: 20,
  },
  threatBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 12,
    paddingHorizontal: 20,
    borderRadius: 12,
    gap: 8,
    marginBottom: 16,
  },
  threatText: {
    fontSize: 18,
    fontWeight: '700',
    color: '#FFFFFF',
  },
  findingsCount: {
    fontSize: 16,
    color: '#8E8E93',
    textAlign: 'center',
    marginBottom: 16,
  },
  findingsList: {
    gap: 12,
  },
  findingItem: {
    backgroundColor: '#2C2C2E',
    borderRadius: 10,
    padding: 14,
  },
  findingHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 6,
  },
  severityDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
  },
  findingType: {
    fontSize: 13,
    fontWeight: '600',
    color: '#FFFFFF',
    flex: 1,
  },
  findingCount: {
    fontSize: 13,
    fontWeight: '600',
    color: '#8E8E93',
  },
  findingDesc: {
    fontSize: 14,
    color: '#AEAEB2',
    marginBottom: 4,
  },
  findingDetail: {
    fontSize: 12,
    color: '#636366',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  safeMessage: {
    alignItems: 'center',
    paddingVertical: 20,
  },
  safeText: {
    fontSize: 20,
    fontWeight: '600',
    color: '#30D158',
    marginTop: 12,
  },
  safeSubtext: {
    fontSize: 14,
    color: '#8E8E93',
    marginTop: 4,
  },
  cleanHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    marginBottom: 16,
  },
  cleanTitle: {
    fontSize: 20,
    fontWeight: '600',
    color: '#30D158',
  },
  statsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginBottom: 16,
  },
  statItem: {
    alignItems: 'center',
  },
  statValue: {
    fontSize: 24,
    fontWeight: '700',
    color: '#FFFFFF',
  },
  statLabel: {
    fontSize: 12,
    color: '#8E8E93',
    marginTop: 4,
  },
  removedList: {
    backgroundColor: '#2C2C2E',
    borderRadius: 10,
    padding: 12,
    marginBottom: 16,
  },
  removedTitle: {
    fontSize: 14,
    fontWeight: '600',
    color: '#FFFFFF',
    marginBottom: 8,
  },
  removedItem: {
    fontSize: 13,
    color: '#AEAEB2',
    marginBottom: 4,
  },
  cleanedTextBox: {
    backgroundColor: '#2C2C2E',
    borderRadius: 10,
    padding: 12,
    marginBottom: 16,
  },
  cleanedLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#FFFFFF',
    marginBottom: 8,
  },
  cleanedScroll: {
    maxHeight: 150,
  },
  cleanedText: {
    fontSize: 14,
    color: '#AEAEB2',
    lineHeight: 20,
  },
  cleanActions: {
    flexDirection: 'row',
    justifyContent: 'center',
    gap: 20,
  },
  cleanActionBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingVertical: 10,
    paddingHorizontal: 16,
    backgroundColor: '#2C2C2E',
    borderRadius: 8,
  },
  cleanActionText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#007AFF',
  },
  infoContainer: {
    flex: 1,
    padding: 16,
  },
  infoTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#FFFFFF',
    marginBottom: 16,
  },
  infoCard: {
    backgroundColor: '#1C1C1E',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  infoCardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    marginBottom: 8,
  },
  infoCardTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#FFFFFF',
  },
  infoCardText: {
    fontSize: 14,
    color: '#AEAEB2',
    lineHeight: 20,
  },
});
