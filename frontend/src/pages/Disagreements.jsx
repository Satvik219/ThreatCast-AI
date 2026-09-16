import React from "react";
import { usePcapAnalysis, buildUploadedRuleComparison } from '../context/PcapAnalysisContext';


export default function Disagreements() {
  const { analysis, fileName } = usePcapAnalysis();
  const pcapComparison = buildUploadedRuleComparison(analysis);
  const activeComparison = pcapComparison || null;
  const isConnected = Boolean(activeComparison);
  const disagreementCount = activeComparison?.total_disagreements ?? 0;

  return (
    <div className="min-h-screen bg-[#fcfaf6] px-5 py-6 md:px-8">

      <div className="mb-6 border-b border-[#ebdcc7] pb-5">

        <div className="flex flex-wrap items-start justify-between gap-4">

          <div>

            <h1 className="text-3xl font-bold tracking-tight text-[#301a0a]">
              Model vs Rule Verification
            </h1>

            <p className="mt-2 max-w-3xl text-sm leading-6 text-[#806b58]">
              Verification status for comparison between the
              CTU13 LSTM early-warning output and a deterministic
              security-rule engine.
            </p>

          </div>


          <div className="rounded-full border border-[#ecd7a5] bg-[#fff7d9] px-4 py-2 text-xs font-semibold text-[#a94d08]">
            {isConnected ? 'PCAP RULES CONNECTED' : 'INTEGRATION PENDING'}
          </div>

        </div>

      </div>


      {/* STATUS */}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">

        <div className="rounded-2xl border border-[#ecd7a5] bg-[#fffaf0] p-6">

          <div className="text-xs font-bold uppercase tracking-wider text-[#a94d08]">
            ML model
          </div>

          <div className="mt-3 text-2xl font-bold text-[#301a0a]">
            CTU13 LSTM
          </div>

          <div className="mt-2 text-sm leading-6 text-[#806b58]">
            Produces an aggregate early-warning probability
            from five consecutive 30-second network states
            using 12 engineered features.
          </div>

        </div>


        <div className="rounded-2xl border border-[#ebdcc7] bg-white p-6">

          <div className="text-xs font-bold uppercase tracking-wider text-[#a94d08]">
            Rule engine
          </div>

          <div className="mt-3 text-2xl font-bold text-[#301a0a]">
            {isConnected ? 'Connected' : 'Not Connected'}
          </div>

          <div className="mt-2 text-sm leading-6 text-[#806b58]">
            {isConnected
              ? `Evaluating ${fileName} with deterministic rules.`
              : 'Upload a CSV or PCAP from the header to connect deterministic rules to the model.'}
          </div>

        </div>

      </div>


      {/* RESULT */}

      <div className="mt-6 rounded-2xl border border-[#ebdcc7] bg-white p-6">

        <div className="text-xs font-bold uppercase tracking-wider text-[#a94d08]">
          Current verification result
        </div>

        <div className="mt-3 text-2xl font-bold text-[#4d7c0f]">
          {isConnected
            ? disagreementCount > 0
              ? `${disagreementCount} Model-Rule Disagreement`
              : 'Model and Rule Agreement'
            : 'No Model-Rule Disagreement Claim'}
        </div>

        <p className="mt-3 max-w-3xl text-sm leading-6 text-[#5f4b39]">

          {isConnected
            ? activeComparison.analytical_summary
            : 'A disagreement is calculated after a PCAP upload provides both the CTU13 LSTM prediction and deterministic flow-evidence rules for the same capture.'}

        </p>

      </div>


      {/* WHY */}

      <div className="mt-6 rounded-2xl border border-[#ebdcc7] bg-white p-6">

        <div className="text-xs font-bold uppercase tracking-wider text-[#a94d08]">
          {isConnected ? 'Uploaded PCAP comparison' : 'Why this is currently zero'}
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">

          <div className="rounded-xl border border-[#ebdcc7] bg-[#fcfaf6] p-4">

            <div className="text-lg font-bold text-[#301a0a]">
              01
            </div>

            <div className="mt-2 text-sm font-semibold text-[#301a0a]">
              LSTM available
            </div>

            <div className="mt-1 text-xs leading-5 text-[#806b58]">
              CTU13 inference is connected to FastAPI.
            </div>

          </div>


          <div className="rounded-xl border border-[#ebdcc7] bg-[#fcfaf6] p-4">

            <div className="text-lg font-bold text-[#301a0a]">
              02
            </div>

            <div className="mt-2 text-sm font-semibold text-[#301a0a]">
              {isConnected ? 'Rule result available' : 'Rule result unavailable'}
            </div>

            <div className="mt-1 text-xs leading-5 text-[#806b58]">
              {isConnected ? `${activeComparison.flagged_flow_count} flagged flow(s) evaluated.` : 'Upload a PCAP to evaluate deterministic flow evidence.'}
            </div>

          </div>


          <div className="rounded-xl border border-[#ebdcc7] bg-[#fcfaf6] p-4">

            <div className="text-lg font-bold text-[#301a0a]">
              03
            </div>

            <div className="mt-2 text-sm font-semibold text-[#301a0a]">
              {isConnected ? 'Comparison active' : 'Comparison disabled'}
            </div>

            <div className="mt-1 text-xs leading-5 text-[#806b58]">
              {isConnected ? `${disagreementCount} disagreement(s) for this PCAP.` : 'No disagreement claim is generated.'}
            </div>

          </div>

        </div>

      </div>


      {/* SCOPE */}

      <div className="mt-6 rounded-2xl border border-[#ecd7a5] bg-[#fffaf0] p-6">

        <div className="text-xs font-bold uppercase tracking-wider text-[#a94d08]">
          Integration note
        </div>

        <p className="mt-2 text-sm leading-6 text-[#5f4b39]">

          {isConnected
            ? 'This comparison uses deterministic flagged-flow evidence from the uploaded PCAP and the first CTU13 world-model forecast horizon.'
            : 'Upload a PCAP from the global header to compare deterministic flow evidence with the CTU13 LSTM classification.'}

        </p>

      </div>

    </div>
  );
}