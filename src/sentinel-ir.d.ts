export type Language = "javascript" | "typescript" | "tsx" | "python" | "rust";
export type LanguageOption = Language | "js" | "ts" | "py" | "rs" | (string & {});
export type Risk = "low" | "medium" | "high" | "critical";
export type AnalysisStatus = "complete" | "incomplete";
export type Objective =
    | "security_refactor"
    | "filesystem_simplification"
    | "network_stability"
    | "stability_repair"
    | "general_optimization";

export interface AnalyzeOptions {
    target?: string;
    language?: LanguageOption;
    pressure?: number;
    confidence?: number;
    budget?: number;
    consecutiveFailures?: number;
}

export interface ParseError {
    line: number;
    column: number;
    kind: "missing" | "unexpected" | "unclosed";
    expected?: string;
}

export interface RiskSignal {
    signal: string;
    evidence: string;
    line: number;
}

export interface Operations {
    inboundHttp: boolean;
    outboundHttp: boolean;
    diskRead: boolean;
    diskWrite: boolean;
    diskDelete: boolean;
    dynamicEval: boolean;
    processSpawn: boolean;
    childProcess: boolean;
    processExit: boolean;
    cryptoUse: boolean;
    secretComparison: boolean;
    unsafeDeserialization: boolean;
    nativeCode: boolean;
    /** Since 0.5.12: require(name), import(url), __import__(name). */
    dynamicImport?: boolean;
    /** Since 0.5.12: global["pro" + "cess"], getattr(os, name). */
    dynamicReference?: boolean;
    /** Since 0.5.12: a name that reads like an instruction to an agent. */
    suspiciousText?: boolean;
}

export interface Facts {
    ast: boolean;
    routes: string[];
    exports: string[];
    imports: string[];
    env: string[];
    calls: {
        network: string[];
        filesystem: string[];
        process: string[];
        crypto: string[];
        dynamic: string[];
    };
    operations: Operations;
    dangerous: string[];
    riskSignals: RiskSignal[];
    parseError?: ParseError;
    error?: string;
    [key: string]: unknown;
}

export interface Summary {
    size: number;
    lines: number;
    hasCrypto: boolean;
    hasFilesystem: boolean;
    hasNetwork: boolean;
}

export interface IR {
    target: string | null;
    language: Language | string;
    objective: Objective;
    constraints: string[];
    risk: Risk;
    pressure: number;
    confidence: number;
    budget: number;
    forbidden: string[];
    summary: Summary;
    analysisStatus: AnalysisStatus;
    facts: Facts;
}

export type CompressedFacts =
    | { ast: false; reason: string; parseError?: ParseError }
    | {
        ast: true;
        routes?: string[];
        exports?: string[];
        imports?: string[];
        env?: string[];
        operations?: (keyof Operations)[];
        calls?: Partial<Facts["calls"]>;
        dangerous?: string[];
        riskSignals?: string[];
    };

export interface CompressedIR {
    analysisStatus: AnalysisStatus;
    language: Language | string;
    mission: { target: string | null; objective: Objective };
    world: { pressure: number; confidence: number; budget: number; risk: Risk };
    constraints: string[];
    forbidden: string[];
    summary: Summary;
    facts: CompressedFacts;
}

export interface Decision {
    action: unknown;
    patch?: unknown;
    [key: string]: unknown;
}

export function analyze(content: string, options?: AnalyzeOptions): IR;
export function analyzeAsync(content: string, options?: AnalyzeOptions): Promise<IR>;
export function initializeWasm(options?: { languages?: LanguageOption[] }): Promise<void>;
export function compress(ir: IR): CompressedIR;
export function compressFacts(facts: Facts): CompressedFacts;
export function expandDecision(decision: Decision, ir: IR): {
    action: unknown;
    patch: unknown;
    target: string | null;
    objective: Objective;
    confidence: number;
    pressure: number;
};
export const DEFAULTS: Readonly<{
    pressure: number;
    confidence: number;
    budget: number;
    consecutiveFailures: number;
}>;
export const LANGUAGES: readonly Language[];
