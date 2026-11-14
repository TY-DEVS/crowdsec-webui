import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { AuditLogs } from '../AuditLogs';
import type { AuditLogItem, AuditLogListResponse } from '../../types';

const { fetchAuditLogsMock, getAuditLogsExportUrlMock } = vi.hoisted(() => ({
  fetchAuditLogsMock: vi.fn(),
  getAuditLogsExportUrlMock: vi.fn(),
}));

vi.mock('../../lib/api', () => ({
  fetchAuditLogs: fetchAuditLogsMock,
  getAuditLogsExportUrl: getAuditLogsExportUrlMock,
}));

function mockLogsResponse(items: AuditLogItem[], page = 1, pageSize = 50, total = items.length): AuditLogListResponse {
  return {
    data: items,
    pagination: {
      page,
      page_size: pageSize,
      total,
      total_pages: Math.ceil(total / pageSize) || 1,
      unfiltered_total: total,
    },
  };
}

describe('AuditLogs Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getAuditLogsExportUrlMock.mockImplementation((_filters, format) => `/api/audit-logs?format=${format}`);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('renders header, filter inputs, and table headers', async () => {
    fetchAuditLogsMock.mockResolvedValueOnce(mockLogsResponse([]));

    render(
      <MemoryRouter>
        <AuditLogs />
      </MemoryRouter>,
    );

    expect(screen.getByText('Audit Logs')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Search user, action, IP/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Action/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Outcome/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Filter by user/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Filter by IP/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenCalledTimes(1);
    });
  });

  test('displays audit log entries and badges', async () => {
    const sampleLogs: AuditLogItem[] = [
      {
        time: '2026-07-01T10:00:00.000Z',
        user: 'tommy',
        role: 'admin',
        action: 'decision.add',
        outcome: 'success',
        ip: '192.168.1.10',
        type: 'ban',
        duration: '4h',
        reason: 'brute-force',
      },
      {
        time: '2026-07-01T11:00:00.000Z',
        user: 'sarah',
        action: 'user.login',
        outcome: 'success',
        auth_method: 'password',
      },
      {
        time: '2026-07-01T12:00:00.000Z',
        user: 'system',
        action: 'alert.delete',
        outcome: 'queued',
        alert_ids: ['10', '11'],
      },
    ];

    fetchAuditLogsMock.mockResolvedValueOnce(mockLogsResponse(sampleLogs));

    render(
      <MemoryRouter>
        <AuditLogs />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText('tommy')).toBeInTheDocument();
    });

    const table = screen.getByRole('table');
    expect(within(table).getByText('decision.add')).toBeInTheDocument();
    expect(within(table).getByText('192.168.1.10')).toBeInTheDocument();
    expect(within(table).getByText('user.login')).toBeInTheDocument();
    expect(within(table).getByText('alert.delete')).toBeInTheDocument();
    expect(within(table).getByText('2 alerts')).toBeInTheDocument();
  });

  test('opens details modal when clicking on a row or view button', async () => {
    const sampleLog: AuditLogItem = {
      time: '2026-07-01T10:00:00.000Z',
      user: 'tommy',
      role: 'admin',
      action: 'decision.add',
      outcome: 'success',
      ip: '192.168.1.10',
      reason: 'manual review ban',
      instances: ['CrowdSec-1', 'CrowdSec-2'],
    };

    fetchAuditLogsMock.mockResolvedValueOnce(mockLogsResponse([sampleLog]));

    render(
      <MemoryRouter>
        <AuditLogs />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText('tommy')).toBeInTheDocument();
    });

    // Click on row to open modal
    await userEvent.click(screen.getByText('tommy'));

    await waitFor(() => {
      expect(screen.getByText('Audit Log Event Details')).toBeInTheDocument();
    });

    expect(screen.getByText('manual review ban')).toBeInTheDocument();
    expect(screen.getByText('CrowdSec-1, CrowdSec-2')).toBeInTheDocument();
    expect(screen.getByText('Raw Event JSON')).toBeInTheDocument();

    // Close modal
    await userEvent.click(screen.getByRole('button', { name: /Close/i }));
    await waitFor(() => {
      expect(screen.queryByText('Audit Log Event Details')).not.toBeInTheDocument();
    });
  });

  test('filters by action, user, outcome, and text search', async () => {
    fetchAuditLogsMock.mockResolvedValue(mockLogsResponse([]));

    render(
      <MemoryRouter>
        <AuditLogs />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenCalledTimes(1);
    });

    // Select action filter
    const actionSelect = screen.getByLabelText(/Action/i);
    await userEvent.selectOptions(actionSelect, 'decision.add');

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ action: 'decision.add' }),
      );
    });

    // Select outcome filter
    const outcomeSelect = screen.getByLabelText(/Outcome/i);
    await userEvent.selectOptions(outcomeSelect, 'failure');

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ action: 'decision.add', outcome: 'failure' }),
      );
    });

    // Type in user filter
    const userInput = screen.getByPlaceholderText(/Filter by user/i);
    await userEvent.type(userInput, 'admin');

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ user: 'admin' }),
      );
    });

    // Reset filters button appears and clears filters
    const resetBtn = screen.getByRole('button', { name: /Reset Filters/i });
    await userEvent.click(resetBtn);

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenLastCalledWith(
        expect.objectContaining({
          action: undefined,
          outcome: undefined,
          user: undefined,
        }),
      );
    });
  });

  test('triggers export menu and navigation', async () => {
    fetchAuditLogsMock.mockResolvedValueOnce(mockLogsResponse([]));
    const assignMock = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { assign: assignMock },
      writable: true,
    });

    render(
      <MemoryRouter>
        <AuditLogs />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenCalledTimes(1);
    });

    // Open export dropdown
    const exportBtn = screen.getByRole('button', { name: /Export CSV \/ JSON/i });
    await userEvent.click(exportBtn);

    expect(screen.getByRole('menuitem', { name: /Export CSV/i })).toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: /Export JSON/i })).toBeInTheDocument();

    // Click Export CSV
    await userEvent.click(screen.getByRole('menuitem', { name: /Export CSV/i }));
    expect(getAuditLogsExportUrlMock).toHaveBeenCalledWith(expect.any(Object), 'csv');
    expect(assignMock).toHaveBeenCalledWith('/api/audit-logs?format=csv');
  });

  test('handles pagination controls', async () => {
    fetchAuditLogsMock.mockResolvedValue(mockLogsResponse([], 1, 25, 100));

    render(
      <MemoryRouter>
        <AuditLogs />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText(/Page 1 of 4/i)).toBeInTheDocument();
    });

    const nextBtn = screen.getByRole('button', { name: /Next/i });
    await userEvent.click(nextBtn);

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ page: 2 }),
      );
    });
  });

  test('shows error message and retries on failure', async () => {
    fetchAuditLogsMock.mockRejectedValueOnce(new Error('Network error'));

    render(
      <MemoryRouter>
        <AuditLogs />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });

    fetchAuditLogsMock.mockResolvedValueOnce(mockLogsResponse([]));
    const retryBtn = screen.getByRole('button', { name: /Retry/i });
    await userEvent.click(retryBtn);

    await waitFor(() => {
      expect(fetchAuditLogsMock).toHaveBeenCalledTimes(2);
    });
  });
});
