import { useState } from 'react';
import { Terminal, Code, Cpu, Book, ArrowRight, Zap, Layers, Globe, Box, CheckCircle } from 'lucide-react';
import './index.css';

const sections = {
  getting_started: {
    title: 'Getting Started',
    icon: <Zap size={18} />,
    content: (
      <div className="markdown-body fade-in">
        <h1 className="gradient-text">Getting Started with SageBatch</h1>
        <p className="lead-text">SageBatch is a modern, high-performance implementation of MS-DOS Batch 4.0, built entirely in SageLang. It aims to provide full compatibility with classic batch scripts while offering the incredible speed and safety guarantees of the SageLang toolchain.</p>
        
        <div className="card-highlight">
          <h2>Installation</h2>
          <p>To start using SageBatch, you'll need the SageLang toolchain installed on your system.</p>
          <pre><code>{`# Clone the repository
git clone https://github.com/Night-Traders-Dev/SageBatch.git
cd SageBatch

# Clean any existing artifacts
./sagemake clean

# Build the native executable
./sagemake build

# Run an interactive REPL
./build/sagebatch

# Execute a script
./build/sagebatch script.bat`}</code></pre>
        </div>

        <h2>Why SageBatch?</h2>
        <div className="grid-list">
          <div className="grid-item">
            <CheckCircle className="text-primary" size={24} />
            <div>
              <h3>Blazing Fast</h3>
              <p>Compiled to native machine code via SageLang's C backend.</p>
            </div>
          </div>
          <div className="grid-item">
            <CheckCircle className="text-secondary" size={24} />
            <div>
              <h3>SageVM Support</h3>
              <p>Can run perfectly in pure bytecode mode for embedded environments.</p>
            </div>
          </div>
          <div className="grid-item">
            <CheckCircle className="text-accent" size={24} />
            <div>
              <h3>Familiar Syntax</h3>
              <p>Supports standard MS-DOS Batch syntax, variables, conditionals, loops, and commands.</p>
            </div>
          </div>
        </div>
      </div>
    )
  },
  sagelang: {
    title: 'SageLang Implementation',
    icon: <Code size={18} />,
    content: (
      <div className="markdown-body fade-in">
        <h1 className="gradient-text">Built in SageLang</h1>
        <p className="lead-text">SageBatch is written entirely in <strong>SageLang</strong>, a Python-inspired systems programming language that compiles to C and LLVM IR.</p>
        
        <h2>Compiler Architecture</h2>
        <p>The interpreter follows a traditional phased compiler design implemented through highly modular `.sage` files:</p>
        
        <div className="timeline">
          <div className="timeline-item">
            <div className="timeline-icon">1</div>
            <div className="timeline-content">
              <h3>Lexer <code>(lexer.sage)</code></h3>
              <p>Tokenizes the raw <code>.bat</code> file into tokens (<code>WORD</code>, <code>VARIABLE</code>, <code>STRING</code>, <code>REDIRECT</code>). Identifies structures like <code>%VAR%</code> vs delayed expansion <code>!VAR!</code>.</p>
            </div>
          </div>
          <div className="timeline-item">
            <div className="timeline-icon">2</div>
            <div className="timeline-content">
              <h3>Parser <code>(parser.sage)</code></h3>
              <p>Constructs an Abstract Syntax Tree (AST) handling batch specifics like nested loops, complex conditionals, and block nodes <code>()</code>.</p>
            </div>
          </div>
          <div className="timeline-item">
            <div className="timeline-icon">3</div>
            <div className="timeline-content">
              <h3>Interpreter <code>(interpreter.sage)</code></h3>
              <p>A recursive tree-walking executor that evaluates AST nodes via the <code>Environment</code> and <code>VarStore</code>.</p>
            </div>
          </div>
        </div>
        
        <h2>AOT Compilation vs Interpreted</h2>
        <p>Because SageLang compiles directly to C via its AOT backend, SageBatch produces a highly optimized, statically linked ELF binary. The runtime string pooling and garbage collector ensure low memory overhead even during complex recursive batch executions.</p>
      </div>
    )
  },
  sagevm: {
    title: 'SageVM Mode',
    icon: <Cpu size={18} />,
    content: (
      <div className="markdown-body fade-in">
        <h1 className="gradient-text">Running in SageVM Mode</h1>
        <p className="lead-text">SageBatch can be compiled into <strong>SageVM bytecode</strong> for execution on embedded systems, bare-metal kernels, and specialized sandboxed environments.</p>

        <div className="card-highlight">
          <h2>Compiling to Bytecode</h2>
          <p>To compile the batch runtime to bytecode:</p>
          <pre><code>{`# Use the Sage compiler to emit SGVM bytecode
sage --sgvm src/sage/batch.sage -o build/sagebatch.sgvm`}</code></pre>

          <h2>Execution</h2>
          <p>Run the VM file using the SageVirtualMachine runtime:</p>
          <pre><code>{`sage --run-vm build/sagebatch.sgvm script.bat`}</code></pre>
        </div>
        
        <div className="info-box">
          <Zap size={24} className="info-icon" />
          <div>
            <h3>100% Feature Parity</h3>
            <p>SageVM runs the AST interpreter logic identically to the native C compilation, meaning scripts execute with identical semantics in both modes.</p>
          </div>
        </div>
      </div>
    )
  },
  components: {
    title: 'Components Guide',
    icon: <Layers size={18} />,
    content: (
      <div className="markdown-body fade-in">
        <h1 className="gradient-text">Internal Components</h1>
        <p className="lead-text">SageBatch is broken down into modular components found in <code>src/sage/</code>, strictly separating responsibilities.</p>
        
        <div className="component-grid">
          <div className="component-card">
            <Box className="component-icon text-primary" size={32} />
            <h3><code>lexer.sage</code></h3>
            <p>Handles the extraction of tokens. It specifically deals with batch variables like <code>%VAR%</code> and delayed expansion <code>!VAR!</code>.</p>
          </div>
          <div className="component-card">
            <Box className="component-icon text-secondary" size={32} />
            <h3><code>parser.sage</code></h3>
            <p>Transforms tokens into AST nodes (<code>IfStatement</code>, <code>ForStatement</code>). Complex syntax like <code>FOR %%A IN (1) DO (...)</code> is parsed here.</p>
          </div>
          <div className="component-card">
            <Box className="component-icon text-accent" size={32} />
            <h3><code>interpreter.sage</code></h3>
            <p>Evaluates AST nodes. Implements Goto jump logic, variable expansion, sub-shell execution via <code>CALL</code>, and redirection.</p>
          </div>
          <div className="component-card">
            <Box className="component-icon text-primary" size={32} />
            <h3><code>registry.sage</code></h3>
            <p>Dispatches commands. Identifies internal commands (<code>ECHO</code>, <code>SET</code>) and delegates to <code>commands.sage</code>.</p>
          </div>
          <div className="component-card">
            <Box className="component-icon text-secondary" size={32} />
            <h3><code>environment.sage</code></h3>
            <p>Holds the DOS environment block, pre-populating PATH, TEMP, COMSPEC, and handling variable expansions.</p>
          </div>
          <div className="component-card">
            <Box className="component-icon text-accent" size={32} />
            <h3><code>varstore.sage</code></h3>
            <p>A stack of dicts that models DOS's flat environment but supports nested FOR loop variables cleanly.</p>
          </div>
        </div>
      </div>
    )
  },
  language: {
    title: 'Language Syntax',
    icon: <Book size={18} />,
    content: (
      <div className="markdown-body fade-in">
        <h1 className="gradient-text">Batch Syntax Reference</h1>
        <p className="lead-text">SageBatch faithfully reproduces MS-DOS Batch 4.0 syntax with modern conveniences.</p>

        <h2>Variables & Expansion</h2>
        <pre><code>{`SET NAME=Jacob
ECHO %NAME%          :: immediate expansion
SETLOCAL ENABLEDELAYEDEXPANSION
SET VAL=hello
ECHO !VAL!           :: delayed expansion
ENDLOCAL`}</code></pre>

        <h2>Control Flow (Labels & GOTO)</h2>
        <p>Label resolution is O(1) via the label table built by the interpreter on the first pass.</p>
        <pre><code>{`:MENU
ECHO 1. Start
ECHO 2. Exit
SET /P CHOICE=Enter choice:
IF %CHOICE%==1 GOTO START
IF %CHOICE%==2 GOTO END
GOTO MENU

:START
ECHO Starting...`}</code></pre>

        <h2>Loops & Iteration</h2>
        <pre><code>{`:: List iteration
FOR %%A IN (apple banana cherry) DO ECHO %%A

:: File globbing
FOR %%F IN (*.txt) DO TYPE %%F`}</code></pre>

        <h2>Redirection</h2>
        <pre><code>{`DIR > listing.txt
DIR >> listing.txt
TYPE file.txt | FIND "ERROR"`}</code></pre>
      </div>
    )
  }
};

function App() {
  const [activeSection, setActiveSection] = useState<string | null>(null);

  if (activeSection === null) {
    return (
      <div className="app-container">
        <header className="glass-header">
          <div className="logo-container">
            <div className="logo-icon-wrapper">
              <Terminal className="logo-icon" size={24} />
            </div>
            <span className="logo-text">SageBatch</span>
          </div>
          <div className="nav-links">
            <span className="nav-link" onClick={() => setActiveSection('getting_started')}>Documentation</span>
            <a href="https://github.com/Night-Traders-Dev/SageBatch" className="nav-link github-btn" target="_blank" rel="noreferrer">
              <Globe size={16} /> GitHub
            </a>
          </div>
        </header>

        <main className="landing-content">
          <div className="glow-sphere sphere-1"></div>
          <div className="glow-sphere sphere-2"></div>
          
          <section className="hero">
            <div className="hero-badge">v1.0.0 Release</div>
            <h1 className="hero-title">The Ultimate DOS <br/><span className="gradient-text">Batch Engine</span></h1>
            <p className="hero-subtitle">Reimagining MS-DOS Batch 4.0 with extreme performance, modern type-safety, and seamless SageVM portability. Completely written in pure SageLang.</p>
            <div className="hero-buttons">
              <button className="btn btn-primary" onClick={() => setActiveSection('getting_started')}>
                Explore Documentation <ArrowRight size={18} />
              </button>
              <button className="btn btn-secondary" onClick={() => window.open('https://github.com/Night-Traders-Dev/SageBatch', '_blank')}>
                <Code size={18} /> View Source
              </button>
            </div>
          </section>

          <section className="features-grid">
            <div className="feature-card glass-card">
              <div className="feature-icon-wrapper bg-primary-dim">
                <Zap className="text-primary" size={28} />
              </div>
              <h3>Native Performance</h3>
              <p>Compiled directly to native C/LLVM via the SageLang compiler for blazing-fast script execution with minimal memory overhead.</p>
            </div>
            <div className="feature-card glass-card">
              <div className="feature-icon-wrapper bg-secondary-dim">
                <Code className="text-secondary" size={28} />
              </div>
              <h3>100% Pure SageLang</h3>
              <p>A full lexer, AST parser, and recursive tree-walk interpreter built from scratch in the beautiful Sage systems language.</p>
            </div>
            <div className="feature-card glass-card">
              <div className="feature-icon-wrapper bg-accent-dim">
                <Cpu className="text-accent" size={28} />
              </div>
              <h3>SageVM Ready</h3>
              <p>Seamlessly compile to SGVM bytecode and run batch scripts on bare-metal kernels, bootloaders, and embedded systems.</p>
            </div>
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="app-container docs-layout">
      <header className="glass-header docs-header">
        <div className="logo-container" style={{ cursor: 'pointer' }} onClick={() => setActiveSection(null)}>
          <div className="logo-icon-wrapper">
            <Terminal className="logo-icon" size={24} />
          </div>
          <span className="logo-text">SageBatch</span>
        </div>
        <div className="nav-links">
          <span className="nav-link active">Docs</span>
          <a href="https://github.com/Night-Traders-Dev/SageBatch" className="nav-link" target="_blank" rel="noreferrer">GitHub</a>
        </div>
      </header>

      <div className="docs-body">
        <aside className="sidebar glass-sidebar">
          <div className="sidebar-content">
            <div className="sidebar-group">
              <span className="sidebar-title">Menu</span>
              {Object.entries(sections).map(([key, section]) => (
                <div 
                  key={key} 
                  className={`sidebar-item ${activeSection === key ? 'active' : ''}`}
                  onClick={() => setActiveSection(key)}
                >
                  <span className="sidebar-item-icon">{section.icon}</span>
                  <span className="sidebar-item-text">{section.title}</span>
                  {activeSection === key && <div className="active-indicator"></div>}
                </div>
              ))}
            </div>
          </div>
        </aside>

        <main className="content-area custom-scrollbar">
          <div className="content-wrapper glass-content">
            {sections[activeSection as keyof typeof sections]?.content}
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
