
%-------------------------
% Resume in Latex
% Author : Omkar Dhamgunde
% Optimized for ATS and FAANG Applications
% License : MIT
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
    \end{tabular*}\vspace{-7pt}
}

\newcommand{\resumeSubItem}[1]{\resumeItem{#1}\vspace{-4pt}}

\renewcommand\labelitemi{$\vcenter{\hbox{\tiny$\bullet$}}$}
\renewcommand\labelitemii{$\vcenter{\hbox{\tiny$\bullet$}}$}

\newcommand{\resumeSubHeadingListStart}{\begin{itemize}[leftmargin=0.0in, label={}]}
\newcommand{\resumeSubHeadingListEnd}{\end{itemize}}
\newcommand{\resumeItemListStart}{\begin{itemize}}
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
    \href{https://leetcode.com/u/omkar_dhamgunde/}{\raisebox{-0.2\height}\faCode\ \underline{LeetCode}}
    \vspace{-8pt}
\end{center}

%-----------SUMMARY-----------
\section{SUMMARY}
\begin{itemize}[leftmargin=0.15in, label={}]
    \item \small{\textbf{A Computer Science student with a strong foundation in full-stack development, data structures, and algorithms.}}
    \item \small{\textbf{Proven ability to build robust, data-driven applications from concept to deployment, with hands-on experience in backend API design and real-time data processing.}}
    \item \small{\textbf{Possesses strong problem-solving and communication skills, demonstrated through complex technical projects and community-focused initiatives.}}
\end{itemize}

%-----------EDUCATION-----------
\section{EDUCATION}
\resumeSubHeadingListStart
    \resumeSubheading
      {Vishwakarma Institute of Technology}{2023 -- 2027}
      {Bachelor of Technology in Computer Science - \textbf{CGPA: 8.62}}{Pune, India}
\resumeSubHeadingListEnd

%-----------PROGRAMMING SKILLS-----------
\section{TECHNICAL SKILLS}
\begin{itemize}[leftmargin=0.15in, label={}]
    \small{\item{
        \textbf{\normalsize{Languages:}}{ \normalsize{Python, Java, C, SQL, HTML, CSS}} \\
        \textbf{\normalsize{Frameworks \& Tools:}}{ \normalsize{FastAPI, Flask, SQLAlchemy, Pandas, Numpy, Git, GitHub, MySQL, VS Code}} \\
        \textbf{\normalsize{Core Concepts:}}{ \normalsize{DSA, OOP, Operating Systems, API Design, Web Development}}
    }}
\end{itemize}

%-----------TECHNICAL EXPERIENCE (PROJECTS)-----------
\section{TECHNICAL EXPERIENCE (PROJECTS)}
\vspace{-5pt}
\resumeSubHeadingListStart
    \resumeProjectHeading
        {\href{https://github.com/omkardhamgunde/Behavioral-Bot-Detection}{\textbf{\large{\underline{Behavioral Bot Detection}}} \href{https://github.com/omkardhamgunde/Behavioral-Bot-Detection}{\raisebox{-0.1\height}\faExternalLink }} $|$ \large{\underline{Python, FastAPI, React, TypeScript, scikit-learn}}}{\href{https://github.com/omkardhamgunde/Behavioral-Bot-Detection}{\raisebox{-0.1\height}\faGithub}}
        \resumeItemListStart
            \resumeItem{\normalsize{Built a multi-layer bot detection system using a \textbf{Random Forest classifier} trained on mouse behavioral features (velocity, acceleration, entropy), \textbf{achieving 85--95\% accuracy} with \textbf{\textless5\% false positive rate}.}}
            \resumeItem{\normalsize{Designed a weighted scoring engine combining ML predictions (70\%) with browser fingerprinting (30\%), tested against \textbf{Selenium, Puppeteer, and headless browser} attack vectors.}}
            \resumeItem{\normalsize{Architected full stack with \textbf{FastAPI + Uvicorn} serving predictions in \textbf{\textless100ms}, React 18 frontend with Recharts, and \textbf{SQLAlchemy + SQLite} for session storage and retraining.}}
        \resumeItemListEnd
        
    \resumeProjectHeading
        {\href{https://github.com/omkardhamgunde/trading}{\textbf{\large{\underline{Trading \& Portfolio Analysis Platform}}} \href{https://github.com/omkardhamgunde/trading}{\raisebox{-0.1\height}\faExternalLink }} $|$ \large{\underline{Python, Flask, MySQL, WebSocket, yfinance API}}}{\href{https://github.com/omkardhamgunde/trading}{\raisebox{-0.1\height}\faGithub}}
        \resumeItemListStart
            \resumeItem{\normalsize{Architected real-time price streaming using \textbf{Flask-SocketIO with gevent} greenlets, pushing live updates every 10 seconds for \textbf{130+ NSE and US equities} via yfinance batch fetching.}}
            \resumeItem{\normalsize{Built a custom \textbf{thread-safe LRU cache (TTL=10s)} reducing Yahoo Finance API calls by 60\%, with \textbf{atomic MySQL transactions} (commit/rollback) for buy/sell execution and dynamic P\&L computation.}}
            \resumeItem{\normalsize{Implemented Google OAuth 2.0 authentication, virtual wallet system, and deployed on \textbf{Gunicorn with gevent workers} for concurrent multi-user handling.}}
        \resumeItemListEnd
\resumeSubHeadingListEnd



%-----------LEADERSHIP & COMMUNITY IMPACT-----------
\section{LEADERSHIP \& COMMUNITY IMPACT}
\resumeSubHeadingListStart
    \resumeSubheading{Digital Literacy Initiative - Technology Educator}{2024}{\underline{Community Outreach \& Ownership}}{Pune, Maharashtra}
        \resumeItemListStart
            \resumeItem{\normalsize{Demonstrated ownership and impact by designing and delivering technology awareness curriculum for \textbf{50+ elderly individuals} across multiple community centers, successfully bridging the digital divide.}}
            \resumeItem{\normalsize{Taught essential digital skills including UPI payment systems, Google Maps navigation, and online government services, \textbf{achieving 90\%+ participant proficiency} in core digital literacy competencies.}}
            \resumeItem{\normalsize{Developed simplified training materials and hands-on workshops tailored to senior citizens, empowering participants to independently access digital services and enhance quality of life.}}
        \resumeItemListEnd
\resumeSubHeadingListEnd

\end{document}