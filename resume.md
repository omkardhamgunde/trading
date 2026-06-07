%-------------------------
% Resume in Latex - Optimized for Finance/Technology Roles
% Tailored for: Technology Internship & Apprenticeship Programs
%------------------------

\documentclass[letterpaper,11pt]{article}

\usepackage{latexsym}
\usepackage[empty]{fullpage}
\usepackage{titlesec}
\usepackage{marvosym}
\usepackage[usenames,dvipsnames]{color}
\usepackage{verbatim}
\usepackage{enumitem}
\usepackage[hidelinks]{hyperref}
\usepackage[english]{babel}
\usepackage{tabularx}
\usepackage{fontawesome5}
\usepackage{multicol}
\usepackage{graphicx}
\setlength{\multicolsep}{-3.0pt}
\setlength{\columnsep}{-1pt}
\usepackage[T1]{fontenc}
\usepackage[default]{plex-sans}
\input{glyphtounicode}

\RequirePackage{tikz}
\RequirePackage{xcolor}
\usepackage{tikz}
\usetikzlibrary{svg.path}

\definecolor{cvblue}{HTML}{0E5484}
\definecolor{black}{HTML}{130810}
\definecolor{darkcolor}{HTML}{0F4539}
\definecolor{cvgreen}{HTML}{3BD80D}
\definecolor{taggreen}{HTML}{00E278}
\definecolor{SlateGrey}{HTML}{2E2E2E}
\definecolor{LightGrey}{HTML}{666666}
\colorlet{name}{black}
\colorlet{tagline}{darkcolor}
\colorlet{heading}{darkcolor}
\colorlet{headingrule}{cvblue}
\colorlet{accent}{darkcolor}
\colorlet{emphasis}{SlateGrey}
\colorlet{body}{LightGrey}

% Adjust margins
\addtolength{\oddsidemargin}{-0.6in}
\addtolength{\evensidemargin}{-0.5in}
\addtolength{\textwidth}{1.19in}
\addtolength{\topmargin}{-.7in}
\addtolength{\textheight}{1.4in}

\urlstyle{same}

\raggedbottom
\raggedright
\setlength{\tabcolsep}{0in}

% Sections formatting
\titleformat{\section}{
  \scshape\raggedright\large\bfseries
}{}{0em}{}[\color{black}\titlerule]
\titlespacing*{\section}{0pt}{10pt plus 2pt minus 2pt}{6pt}

% Ensure that generate pdf is machine readable/ATS parsable
\pdfgentounicode=1

%-------------------------
% Custom commands
\newcommand{\resumeItem}[1]{
  \item\small{
    {#1 \vspace{-2pt}}
  }
}

\newcommand{\classesList}[4]{
    \item\small{
        {#1 #2 #3 #4 \vspace{-2pt}}
    }
}

\newcommand{\resumeSubheading}[4]{
  \vspace{-2pt}\item
    \begin{tabular*}{1.0\textwidth}[t]{l@{\extracolsep{\fill}}r}
      \textbf{\large#1} & \textbf{\small #2} \\
      \textit{\large#3} & \textit{\small #4} \\
    \end{tabular*}\vspace{-7pt}
}

\newcommand{\resumeSubSubheading}[2]{
    \item
    \begin{tabular*}{0.97\textwidth}{l@{\extracolsep{\fill}}r}
      \textit{\small#1} & \textit{\small #2} \\
    \end{tabular*}\vspace{-7pt}
}

\newcommand{\resumeProjectHeading}[2]{
    \item
    \begin{tabular*}{1.001\textwidth}{l@{\extracolsep{\fill}}r}
      \small#1 & \textbf{\small #2}\\
    \end{tabular*}\vspace{-5pt}
}

\newcommand{\resumeSubItem}[1]{\resumeItem{#1}\vspace{-4pt}}

\renewcommand\labelitemi{$\vcenter{\hbox{\tiny$\bullet$}}$}
\renewcommand\labelitemii{$\vcenter{\hbox{\tiny$\bullet$}}$}

\newcommand{\resumeSubHeadingListStart}{\begin{itemize}[leftmargin=0.0in, label={}]}
\newcommand{\resumeSubHeadingListEnd}{\end{itemize}}
\newcommand{\resumeItemListStart}{\begin{itemize}[itemsep=0pt]\nopagebreak}
\newcommand{\resumeItemListEnd}{\end{itemize}\vspace{-5pt}}

\newcommand\sbullet[1][.5]{\mathbin{\vcenter{\hbox{\scalebox{#1}{$\bullet$}}}}}

%-------------------------------------------
%%%%%%  RESUME STARTS HERE  %%%%%%%%%%%%%%%%%%%%%%%%%%%%

\begin{document}

%----------HEADING----------
\begin{center}
    {\Huge \scshape Omkar Dhamgunde} \\ \vspace{1pt}
    Pune, Maharashtra \\ \vspace{1pt}
    \small \href{tel:+919226731744}{ \raisebox{-0.1\height}\faPhone\ \underline{+919226731744} ~} \href{mailto:omkardhamgunde@gmail.com}{\raisebox{-0.2\height}\faEnvelope\  \underline{omkardhamgunde@gmail.com}} ~
    \href{https://www.linkedin.com/in/omkar-dhamgunde}{\raisebox{-0.2\height}\faLinkedin\ \underline{LinkedIn}}  ~
    \href{https://leetcode.com/u/omkar_dhamgunde/}{\raisebox{-0.2\height}\faCode\ \underline{LeetCode}}  ~
    \href{https://github.com/omkardhamgunde}{\raisebox{-0.2\height}\faGithub\ \underline{GitHub}}
    \vspace{-8pt}
\end{center}

%-----------SUMMARY-----------
\section{SUMMARY}
\begin{itemize}[leftmargin=0.15in, label={}]
    \item \small{CS student with hands-on experience building real-time financial data systems using \textbf{Python} and \textbf{SQL}.}
    \item \small{Built a live trading platform processing market data across NSE/US equities with \textbf{WebSocket streaming} and \textbf{OOP design patterns}.}
    \item \small{Strong foundation in \textbf{Data Structures \& Algorithms} (1200+ LeetCode Questions, Knight rank).}
\end{itemize}

%-----------EDUCATION-----------
\section{EDUCATION}
\resumeSubHeadingListStart
    \resumeSubheading
      {Vishwakarma Institute of Technology}{2023 -- 2027}
      {Bachelor of Technology in Computer Science - \textbf{CGPA: 8.66/10}}{Pune, India}
\resumeSubHeadingListEnd

%-----------CODING ACHIEVEMENTS-----------
\section{CODING ACHIEVEMENTS}
\resumeSubHeadingListStart
    \resumeSubheading{Problem Solving \& DSA}{Ongoing}{\href{https://leetcode.com/u/omkar_dhamgunde/}{\underline{LeetCode}}}{1200+ Problems}
        \resumeItemListStart
            \resumeItem{\normalsize{Solved \textbf{1200+} DSA problems on LeetCode and attained \textbf{Knight} rank (peak rating: \textbf{2078}).}}
            \resumeItem{\normalsize{Ranked \textbf{643 / 44,503} globally (\textbf{Top 1.4\%}) in LeetCode \textbf{Weekly Contest 488}.}}
        \resumeItemListEnd
\resumeSubHeadingListEnd

%-----------PROGRAMMING SKILLS-----------
\section{TECHNICAL SKILLS}
\begin{itemize}[leftmargin=0.15in, label={}]
    \small{\item{
        \textbf{\normalsize{Languages:}}{ \normalsize{Python, SQL, Java, C}} \\
        \textbf{\normalsize{Frameworks \& Libraries:}}{ \normalsize{Flask, FastAPI, SQLAlchemy}} \\
        \textbf{\normalsize{Databases:}}{ \normalsize{MySQL, SQLite}} \\
        \textbf{\normalsize{Tools \& Platforms:}}{ \normalsize{Git, GitHub, Postman}} \\
        \textbf{\normalsize{Core Concepts:}}{ \normalsize{DSA, OOP, DBMS, Operating Systems, REST API Design, Computer Networks}}
    }}
\end{itemize}

%-----------TECHNICAL EXPERIENCE (PROJECTS)-----------
\section{TECHNICAL EXPERIENCE (PROJECTS)}
\resumeSubHeadingListStart
    \resumeProjectHeading
        {\href{https://github.com/omkardhamgunde/trading}{\textbf{\large{\underline{Trading \& Portfolio Analysis Platform}}} \href{https://github.com/omkardhamgunde/trading}{\raisebox{-0.1\height}\faExternalLink }} $|$ \large{\underline{Python, Flask, MySQL, WebSocket, yfinance API}}}{\href{https://github.com/omkardhamgunde/trading}{\raisebox{-0.1\height}\faGithub}}
        \resumeItemListStart
            \resumeItem{\normalsize{Built \textbf{Flask} trading simulator with \textbf{10+ REST routes}, \textbf{Flask-SocketIO} streaming, and live watchlists for \textbf{850+ instruments} \& \textbf{4 indices}.}}
            \resumeItem{\normalsize{Optimized \textbf{yfinance} polling with \textbf{thread-safe TTL/LRU cache}, cutting external calls by \textbf{50--75\% vs. 10s uncached per-client polling}.}}
            \resumeItem{\normalsize{Engineered \textbf{autocomplete stock search} across NSE/US/Crypto assets using Yahoo metadata, category filters, and ticker normalization.}}
            \resumeItem{\normalsize{Implemented \textbf{atomic MySQL transactions}, password hashing, \textbf{CSRF-safe WTForms}, rate limiting, \textbf{pytest/GitHub Actions CI}, and \textbf{Gunicorn/gevent} deployment.}}
        \resumeItemListEnd
        
    \resumeProjectHeading
        {\href{https://github.com/omkardhamgunde/Behavioral-Bot-Detection}{\textbf{\large{\underline{Behavioral Bot Detection System}}} \href{https://github.com/omkardhamgunde/Behavioral-Bot-Detection}{\raisebox{-0.1\height}\faExternalLink }} $|$ \large{\underline{Python, FastAPI, React, TypeScript, scikit-learn}}}{\href{https://github.com/omkardhamgunde/Behavioral-Bot-Detection}{\raisebox{-0.1\height}\faGithub}}
        \resumeItemListStart
            \resumeItem{\normalsize{Built \textbf{3-layer detection} (ML, fingerprinting, honeypots) achieving \textbf{85--95\% accuracy} with \textbf{\textless{}5\% false positive rate}.}}
            \resumeItem{\normalsize{Tested against \textbf{7+ bots} (Selenium, Playwright), gaining \textbf{20--30\% accuracy over single-method} via weighted scoring.}}
            \resumeItem{\normalsize{Architected \textbf{Real-time Dashboard} displaying live bot detection metrics, threat indicators, and browser fingerprint analysis.}}
            \resumeItem{\normalsize{Developed full-stack \textbf{FastAPI} app serving predictions in \textbf{\textless{}100ms}, session tracking via \textbf{SQLAlchemy}, and \textbf{4 test scripts}.}}
        \resumeItemListEnd
\resumeSubHeadingListEnd

%-----------LEADERSHIP & ACTIVITIES---------------
\section{LEADERSHIP \& COMMUNITY IMPACT}
\resumeSubHeadingListStart
    \resumeSubheading{Digital Literacy Initiative - Technology Educator}{2024}{\underline{Community Outreach \& Social Impact}}{Pune, Maharashtra}
        \resumeItemListStart
            \resumeItem{\normalsize{Delivered technology awareness curriculum for \textbf{50+ elderly individuals} across multiple community centers.}}
            \resumeItem{\normalsize{Taught UPI payments and e-governance, achieving \textbf{90\%+ proficiency}, demonstrating commitment to \textbf{diversity \& inclusion}.}}
        \resumeItemListEnd
\resumeSubHeadingListEnd

\end{document}
