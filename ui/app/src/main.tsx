import React from 'react'
import { createRoot } from 'react-dom/client'

import './index.css'
import App from './App'
import { initToken } from './api'

const hasToken = initToken()

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App hasToken={hasToken} />
  </React.StrictMode>,
)
