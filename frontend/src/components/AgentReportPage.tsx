import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ChevronLeft, FileText, Download, Calendar, ShieldCheck, AlertCircle } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { idsApi } from '../utils/api';

export default function AgentReportPage() {
  const { reportId } = useParams<{ reportId: string }>();
  const [report, setReport] = useState<{ content: string; name?: string; created_at?: string } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReport = async () => {
      if (!reportId) return;
      try {
        const response = await idsApi.getReportById(reportId);
        setReport(response.data);
      } catch (error) {
        console.error('Failed to fetch report:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [reportId]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-primary" />
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6 space-y-6 max-w-4xl mx-auto">
      <Link to="/" className="flex items-center gap-2 text-slate-500 hover:text-white transition-colors mb-4">
        <ChevronLeft size={16} />
        Back to Dashboard
      </Link>

      <div className="glass rounded-2xl p-8 space-y-6">
        <div className="flex justify-between items-start">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-xl bg-primary/10">
              <ShieldCheck className="text-primary" size={32} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Security Incident Report</h1>
              <div className="flex items-center gap-4 mt-2 text-slate-500 text-sm">
                <span className="flex items-center gap-1"><Calendar size={14} /> {report?.created_at ? new Date(report.created_at).toLocaleDateString() : new Date().toLocaleDateString()}</span>
                <span className="flex items-center gap-1"><FileText size={14} /> ID: {reportId}</span>
              </div>
            </div>
          </div>
          <button className="glass px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 hover:bg-white/5">
            <Download size={16} /> Download PDF
          </button>
        </div>

        <div className="border-t border-white/5 pt-8 space-y-8 prose prose-invert max-w-none">
           {report ? (
             <div className="markdown-content">
               <ReactMarkdown>{report.content}</ReactMarkdown>
             </div>
           ) : (
             <div className="text-center py-12 text-slate-500">
               <AlertCircle className="mx-auto mb-4 opacity-20" size={48} />
               <p>Report content could not be loaded or is empty.</p>
             </div>
           )}
        </div>
      </div>
    </div>
  );
}
