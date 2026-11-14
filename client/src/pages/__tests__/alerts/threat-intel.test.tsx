import './harness';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import * as api from '../../../lib/api';
import { Alerts } from '../../Alerts';

describe('Alert details threat intelligence overlay', () => {
  test('displays threat reputation score, confidence, and badges when alert details open', async () => {
    vi.mocked(api.fetchAlert).mockResolvedValueOnce({
      id: 1,
      created_at: '2026-03-23T11:00:00.000Z',
      scenario: 'crowdsecurity/ssh-bf',
      machine_id: 'machine-1',
      source: { ip: '198.51.100.77', value: '198.51.100.77', cn: 'US', as_name: 'Example AS' },
      target: 'ssh',
      decisions: [],
      events: [],
    });

    vi.mocked(api.fetchThreatIntelLookup).mockResolvedValueOnce({
      ip: '198.51.100.77',
      score: 88,
      confidence: 'high',
      reputation: 'malicious',
      badges: [
        { id: 'scanner', label: 'Known Scanner', variant: 'warning' },
        { id: 'tor', label: 'Tor Node', variant: 'info' },
        { id: 'vpn', label: 'VPN / Proxy', variant: 'secondary' },
      ],
      behaviors: ['tcp:scan', 'ssh:bruteforce'],
      providers: {
        crowdsec: {
          name: 'crowdsec',
          score: 88,
          confidence: 'high',
          reputation: 'malicious',
        },
      },
      cached: false,
      cachedAt: '2026-03-23T11:00:00.000Z',
    });

    render(
      <MemoryRouter initialEntries={['/alerts?id=1']}>
        <Alerts />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(api.fetchThreatIntelLookup).toHaveBeenCalledWith('198.51.100.77');
    });

    // Score & Reputation
    await waitFor(() => {
      expect(screen.getByText(/88/)).toBeInTheDocument();
      expect(screen.getByText(/malicious/i)).toBeInTheDocument();
      expect(screen.getByText(/confidence: high/i)).toBeInTheDocument();
    });

    // Badges
    expect(screen.getByText('Known Scanner')).toBeInTheDocument();
    expect(screen.getByText('Tor Node')).toBeInTheDocument();
    expect(screen.getByText('VPN / Proxy')).toBeInTheDocument();
  });

  test('handles threat intelligence lookup failure gracefully', async () => {
    vi.mocked(api.fetchAlert).mockResolvedValueOnce({
      id: 2,
      created_at: '2026-03-23T11:00:00.000Z',
      scenario: 'crowdsecurity/http-bf',
      source: { ip: '198.51.100.99', value: '198.51.100.99' },
      target: 'http',
      decisions: [],
      events: [],
    });

    vi.mocked(api.fetchThreatIntelLookup).mockRejectedValueOnce(new Error('Network error'));

    render(
      <MemoryRouter initialEntries={['/alerts?id=2']}>
        <Alerts />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(api.fetchThreatIntelLookup).toHaveBeenCalledWith('198.51.100.99');
    });

    // The modal should still render without crashing
    expect(screen.getByText('198.51.100.99')).toBeInTheDocument();
  });

  test('displays clean reputation and private network badges', async () => {
    vi.mocked(api.fetchAlert).mockResolvedValueOnce({
      id: 3,
      created_at: '2026-03-23T11:00:00.000Z',
      scenario: 'crowdsecurity/scan',
      source: { ip: '10.0.0.1', value: '10.0.0.1' },
      target: 'internal',
      decisions: [],
      events: [],
    });

    vi.mocked(api.fetchThreatIntelLookup).mockResolvedValueOnce({
      ip: '10.0.0.1',
      score: 0,
      confidence: 'none',
      reputation: 'benign',
      badges: [
        { id: 'private', label: 'Private IP', variant: 'outline' },
      ],
      behaviors: [],
      providers: {},
      cached: false,
      cachedAt: '2026-03-23T11:00:00.000Z',
    });

    render(
      <MemoryRouter initialEntries={['/alerts?id=3']}>
        <Alerts />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(api.fetchThreatIntelLookup).toHaveBeenCalledWith('10.0.0.1');
    });

    await waitFor(() => {
      expect(screen.getByText('Private IP')).toBeInTheDocument();
      expect(screen.getByText(/benign/i)).toBeInTheDocument();
    });
  });
});

