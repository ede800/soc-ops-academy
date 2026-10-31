import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import './index.css'
import { ProgressProvider } from './lib/progress'
import { CheatSheets } from './views/CheatSheets'
import { CyberLab } from './views/CyberLab'
import { Dashboard } from './views/Dashboard'
import { MitreExplorer } from './views/MitreExplorer'
import { ModuleDetail, ModulesList } from './views/Modules'
import { PlaybookDetail, PlaybooksList } from './views/Playbooks'
import { ReportGenerator } from './views/ReportGenerator'
import { SocQueue, SocTicket } from './views/SocQueue'

// HashRouter : GitHub Pages ne sait pas rediriger les URL profondes vers index.html.
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ProgressProvider>
      <HashRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/modules" element={<ModulesList />} />
            <Route path="/modules/:id" element={<ModuleDetail />} />
            <Route path="/soc-queue" element={<SocQueue />} />
            <Route path="/soc-queue/:id" element={<SocTicket />} />
            <Route path="/cyberlab" element={<CyberLab />} />
            <Route path="/mitre" element={<MitreExplorer />} />
            <Route path="/playbooks" element={<PlaybooksList />} />
            <Route path="/playbooks/:id" element={<PlaybookDetail />} />
            <Route path="/cheat-sheets" element={<CheatSheets />} />
            <Route path="/rapport" element={<ReportGenerator />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout>
      </HashRouter>
    </ProgressProvider>
  </StrictMode>,
)
