import {Button, Card, Input} from '@plunk/ui';
import {DashboardLayout} from '../../components/DashboardLayout';
import {network} from '../../lib/network';
import {NextSeo} from 'next-seo';
import Link from 'next/link';
import {useCallback, useEffect, useMemo, useState} from 'react';
import {Loader2, RefreshCw, Search} from 'lucide-react';
import {toast} from 'sonner';

interface ErpLead {
  erp_lead_id: string;
  email: string;
  lead_name?: string;
  first_name?: string;
  company_name?: string;
  mobile_no?: string;
  store_size?: string;
  pincode?: string;
}

interface ErpLeadResponse {
  leads: ErpLead[];
  total: number;
  truncated?: boolean;
}

interface SubscribeLeadsResult {
  created: number;
  updated: number;
  skippedWithoutEmail: number;
  skippedUnsubscribed: number;
  failed: number;
}

const PAGE_SIZE = 50;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function ContactsPage() {
  const [leads, setLeads] = useState<ErpLead[]>([]);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [truncated, setTruncated] = useState(false);
  const [selectedLeadIds, setSelectedLeadIds] = useState<Set<string>>(new Set());
  const [subscribing, setSubscribing] = useState(false);

  const loadLeads = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await network.fetch<ErpLeadResponse>('GET', '/contacts/erp-leads');
      setLeads(result.leads);
      setTruncated(Boolean(result.truncated));
      setSelectedLeadIds(new Set());
      setPage(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load ERP Leads');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadLeads();
  }, [loadLeads]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return leads;
    return leads.filter(lead => [
      lead.erp_lead_id,
      lead.email,
      lead.lead_name,
      lead.first_name,
      lead.company_name,
      lead.mobile_no,
      lead.store_size,
      lead.pincode,
    ].some(value => String(value ?? '').toLowerCase().includes(query)));
  }, [leads, search]);

  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);
  const pageLeads = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selectablePageLeads = pageLeads.filter(lead => EMAIL_PATTERN.test(lead.email || ''));
  const selectedEmailLeadIds = [...selectedLeadIds].filter(id =>
    leads.some(lead => lead.erp_lead_id === id && EMAIL_PATTERN.test(lead.email || '')),
  );
  const allSelectablePageLeadsSelected = selectablePageLeads.length > 0 &&
    selectablePageLeads.every(lead => selectedLeadIds.has(lead.erp_lead_id));

  const toggleLead = (leadId: string) => {
    setSelectedLeadIds(current => {
      const next = new Set(current);
      if (next.has(leadId)) next.delete(leadId);
      else next.add(leadId);
      return next;
    });
  };

  const togglePageLeads = () => {
    setSelectedLeadIds(current => {
      const next = new Set(current);
      for (const lead of selectablePageLeads) {
        if (allSelectablePageLeadsSelected) next.delete(lead.erp_lead_id);
        else next.add(lead.erp_lead_id);
      }
      return next;
    });
  };

  const subscribeSelected = async () => {
    if (!selectedEmailLeadIds.length || subscribing) return;
    if (!window.confirm(
      `Add ${selectedEmailLeadIds.length} selected Lead email${selectedEmailLeadIds.length === 1 ? '' : 's'} to this Plunk project as subscribed? No email will be sent now. Only subscribe people who have agreed to receive your emails. Previously unsubscribed contacts will remain unsubscribed.`,
    )) return;

    setSubscribing(true);
    try {
      const result = await network.fetch<SubscribeLeadsResult, any>(
        'POST',
        '/contacts/erp-leads/subscribe',
        {leadIds: selectedEmailLeadIds},
      );
      setSelectedLeadIds(new Set());
      const parts = [];
      if (result.created) parts.push(`${result.created} added`);
      if (result.updated) parts.push(`${result.updated} updated`);
      if (result.skippedUnsubscribed) parts.push(`${result.skippedUnsubscribed} already unsubscribed`);
      if (result.skippedWithoutEmail) parts.push(`${result.skippedWithoutEmail} without a valid email`);
      if (result.failed) parts.push(`${result.failed} failed`);
      toast.success(parts.join(' · ') || 'No contacts changed');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not subscribe the selected Leads');
    } finally {
      setSubscribing(false);
    }
  };

  return (
    <>
      <NextSeo title="ERP Leads" />
      <DashboardLayout>
        <div className="space-y-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h1 className="text-2xl font-bold text-neutral-900 sm:text-3xl">ERP Leads</h1>
              <p className="mt-2 text-sm text-neutral-500 sm:text-base">
                Live read-only view of all leads from ERPNext.
              </p>
            </div>
            <div className="flex gap-2">
              {selectedEmailLeadIds.length > 0 && (
                <Button onClick={() => void subscribeSelected()} disabled={subscribing}>
                  {subscribing && <Loader2 className="h-4 w-4 animate-spin" />}
                  Subscribe selected ({selectedEmailLeadIds.length})
                </Button>
              )}
              <Button variant="outline" onClick={() => void loadLeads()} disabled={loading}>
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                Refresh
              </Button>
              <Link href="/contacts/subscribers" className="inline-flex h-10 items-center rounded-md border border-neutral-200 px-3 text-sm font-medium text-neutral-700 hover:bg-neutral-50">
                Email subscribers
              </Link>
            </div>
          </div>

          <Card>
            <div className="flex items-center gap-4 border-b border-neutral-200 px-5 py-4">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-neutral-400" />
                <Input
                  value={search}
                  onChange={event => { setSearch(event.target.value); setPage(0); }}
                  placeholder="Search leads by name, email, company, or phone..."
                  className="pl-10"
                />
              </div>
              <span className="whitespace-nowrap text-sm text-neutral-500">{filtered.length.toLocaleString()} leads</span>
            </div>

            {error ? (
              <div className="p-8 text-center">
                <p className="text-sm text-red-600">{error}</p>
                <p className="mt-2 text-xs text-neutral-500">Check the Plunk server’s ERPNext URL, API credentials, and Lead read permissions.</p>
                <Button className="mt-4" variant="outline" onClick={() => void loadLeads()}>Try again</Button>
              </div>
            ) : loading ? (
              <div className="flex items-center justify-center gap-2 p-12 text-sm text-neutral-500">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading leads from ERPNext…
              </div>
            ) : pageLeads.length === 0 ? (
              <div className="p-12 text-center text-sm text-neutral-500">
                {search ? 'No leads match your search.' : 'ERPNext returned no leads.'}
              </div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[900px] text-left text-sm">
                    <thead className="bg-neutral-50 text-xs uppercase text-neutral-500">
                      <tr>
                        <th className="w-12 px-4 py-3">
                          <input
                            type="checkbox"
                            aria-label="Select all Leads with email on this page"
                            checked={allSelectablePageLeadsSelected}
                            onChange={togglePageLeads}
                            disabled={!selectablePageLeads.length || subscribing}
                            className="rounded border-neutral-300"
                          />
                        </th>
                        <th className="px-5 py-3">Lead</th>
                        <th className="px-5 py-3">Email</th>
                        <th className="px-5 py-3">Company</th>
                        <th className="px-5 py-3">Phone</th>
                        <th className="px-5 py-3">Store size</th>
                        <th className="px-5 py-3">Pincode</th>
                        <th className="px-5 py-3">ERP ID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-neutral-200">
                      {pageLeads.map(lead => (
                        <tr key={lead.erp_lead_id || lead.email} className="hover:bg-neutral-50">
                          <td className="px-4 py-3">
                            <input
                              type="checkbox"
                              aria-label={`Select ${lead.lead_name || lead.email || lead.erp_lead_id}`}
                              checked={selectedLeadIds.has(lead.erp_lead_id)}
                              onChange={() => toggleLead(lead.erp_lead_id)}
                              disabled={!EMAIL_PATTERN.test(lead.email || '') || subscribing}
                              title={EMAIL_PATTERN.test(lead.email || '') ? 'Select this Lead to add it to Plunk' : 'This Lead has no valid email address'}
                              className="rounded border-neutral-300 disabled:cursor-not-allowed disabled:opacity-40"
                            />
                          </td>
                          <td className="px-5 py-3 font-medium text-neutral-900">{lead.lead_name || lead.first_name || '—'}</td>
                          <td className="px-5 py-3 text-neutral-700">{lead.email || '—'}</td>
                          <td className="px-5 py-3 text-neutral-700">{lead.company_name || '—'}</td>
                          <td className="px-5 py-3 text-neutral-700">{lead.mobile_no || '—'}</td>
                          <td className="px-5 py-3 text-neutral-700">{lead.store_size || '—'}</td>
                          <td className="px-5 py-3 text-neutral-700">{lead.pincode || '—'}</td>
                          <td className="px-5 py-3 text-neutral-500">{lead.erp_lead_id || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="flex items-center justify-between border-t border-neutral-200 px-5 py-3 text-sm text-neutral-500">
                  <span>
                    {filtered.length ? `${(page * PAGE_SIZE + 1).toLocaleString()}–${Math.min((page + 1) * PAGE_SIZE, filtered.length).toLocaleString()} of ${filtered.length.toLocaleString()}` : '0 leads'}
                    {truncated && <span className="ml-2 text-amber-700">Showing the first 10,000 Leads.</span>}
                  </span>
                  <div className="flex gap-2">
                    <Button variant="outline" disabled={page === 0} onClick={() => setPage(current => current - 1)}>Previous</Button>
                    <Button variant="outline" disabled={page + 1 >= pageCount} onClick={() => setPage(current => current + 1)}>Next</Button>
                  </div>
                </div>
              </>
            )}
          </Card>
        </div>
      </DashboardLayout>
    </>
  );
}
