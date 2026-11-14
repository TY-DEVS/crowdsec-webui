import { createDefaultConfigResponse } from './harness';
import { describe, expect, test, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import * as api from '../../../lib/api';
import { Decisions } from '../../Decisions';

function configureThreeInstances() {
  const config = createDefaultConfigResponse();
  vi.mocked(api.fetchConfig).mockResolvedValue({
    ...config,
    instances: [
      { id: 'inst-1', name: 'Instance 1', lapi_status: config.lapi_status, sync_status: config.sync_status, prometheus: [] },
      { id: 'inst-2', name: 'Instance 2', lapi_status: config.lapi_status, sync_status: config.sync_status, prometheus: [] },
      { id: 'inst-3', name: 'Instance 3', lapi_status: config.lapi_status, sync_status: config.sync_status, prometheus: [] },
    ],
  });
}

const renderDecisions = (path: string) => render(
  <MemoryRouter initialEntries={[path]}><Decisions /></MemoryRouter>,
);

describe('fleet decision targeting and propagation', () => {
  test('allows selecting custom instances and sends selected scope with instance_ids', async () => {
    configureThreeInstances();
    vi.mocked(api.addDecision).mockResolvedValue(undefined);
    renderDecisions('/decisions?instance=inst-1');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Add Decision' })).toBeInTheDocument());

    await userEvent.click(screen.getByRole('button', { name: 'Add Decision' }));
    const dialog = screen.getByRole('dialog', { name: 'Add Manual Decision' });

    // Type the IP
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'IP / Range' }), '198.51.100.99');

    // Instance 1 is currently active. Click on Instance 2 pill/button to also select it.
    const inst2Button = within(dialog).getByRole('button', { name: /Instance 2/i });
    await userEvent.click(inst2Button);

    // Submit
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add Decision' }));

    await waitFor(() => expect(api.addDecision).toHaveBeenCalledWith({
      ip: '198.51.100.99',
      duration: '4h',
      type: 'ban',
      reason: 'manual',
      scenario: 'manual/web-ui',
      scope: 'selected',
      instance_ids: expect.arrayContaining(['inst-1', 'inst-2']),
    }));
  });

  test('renders propagate button on active decision rows and opens pre-filled fleet modal', async () => {
    configureThreeInstances();
    vi.mocked(api.fetchDecisionsPaginated).mockResolvedValue({
      data: [
        {
          id: 42,
          created_at: new Date().toISOString(),
          value: '198.51.100.77',
          machine: 'edge-gateway',
          scenario: 'crowdsecurity/ssh-bf',
          message: 'Blocked ssh brute-force',
          expired: false,
          is_duplicate: false,
          simulated: false,
          instance_id: 'inst-1',
          instance_name: 'Instance 1',
          detail: {
            action: 'ban',
            origin: 'crowdsec',
            duration: '4h',
            expiration: new Date(Date.now() + 3600000).toISOString(),
            alert_id: 100,
          },
        },
      ],
      pagination: { page: 1, page_size: 50, total: 1, total_pages: 1, unfiltered_total: 1 },
      selectable_ids: [42],
    });

    renderDecisions('/decisions');
    await waitFor(() => expect(screen.getByText('198.51.100.77')).toBeInTheDocument());

    // Look for the fleet propagate button on the row
    const propagateButton = screen.getByRole('button', { name: 'Propagate ban to all instances' });
    expect(propagateButton).toBeInTheDocument();

    await userEvent.click(propagateButton);

    const dialog = screen.getByRole('dialog', { name: 'Add Manual Decision' });
    expect(dialog).toBeInTheDocument();

    // Verify fields are pre-filled
    expect(within(dialog).getByRole('textbox', { name: 'IP / Range' })).toHaveValue('198.51.100.77');
    expect(within(dialog).getByRole('checkbox', { name: 'All instances' })).toBeChecked();
  });
});
