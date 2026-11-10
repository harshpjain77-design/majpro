import React, { useState, useEffect, useCallback } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

export const AppLayout: React.FC = () => {
  const location = useLocation();

  // Responsive state detection
  const [windowWidth, setWindowWidth] = useState<number>(() =>
    typeof window !== 'undefined' ? window.innerWidth : 1200
  );
  
  // Track collapse state; on tablet (768-1024), collapsed by default
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      return window.innerWidth >= 768 && window.innerWidth <= 1024;
    }
    return false;
  });

  // Mobile drawer open state (<768px)
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState<boolean>(false);

  const isMobile = windowWidth < 768;
  const isTablet = windowWidth >= 768 && windowWidth <= 1024;

  const handleResize = useCallback(() => {
    const width = window.innerWidth;
    setWindowWidth(width);
    if (width >= 768 && mobileDrawerOpen) {
      setMobileDrawerOpen(false);
    }
    if (width >= 768 && width <= 1024 && !collapsed) {
      setCollapsed(true);
    }
  }, [mobileDrawerOpen, collapsed]);

  useEffect(() => {
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [handleResize]);

  // Close mobile drawer on route change
  useEffect(() => {
    if (isMobile && mobileDrawerOpen) {
      setMobileDrawerOpen(false);
    }
  }, [location.pathname, isMobile]);

  const handleToggleSidebar = () => {
    if (isMobile) {
      setMobileDrawerOpen((prev) => !prev);
    } else {
      setCollapsed((prev) => !prev);
    }
  };

  const handleCloseMobile = () => {
    setMobileDrawerOpen(false);
  };

  return (
    <div
      style={{
        display: 'flex',
        height: '100vh',
        width: '100vw',
        overflow: 'hidden',
        backgroundColor: 'var(--bg-app, #0a0e1a)',
        color: 'var(--text-primary, #f9fafb)',
        fontFamily: 'var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif)'
      }}
    >
      {/* Mobile Backdrop Overlay */}
      {isMobile && mobileDrawerOpen && (
        <div
          onClick={handleCloseMobile}
          aria-label="Close sidebar backdrop"
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(3px)',
            zIndex: 90,
            transition: 'opacity 0.25s ease'
          }}
        />
      )}

      {/* Sidebar container */}
      <div
        style={{
          position: isMobile ? 'fixed' : 'relative',
          top: 0,
          left: 0,
          bottom: 0,
          zIndex: isMobile ? 100 : 30,
          transform: isMobile
            ? mobileDrawerOpen
              ? 'translateX(0)'
              : 'translateX(-100%)'
            : 'none',
          transition: isMobile ? 'transform 0.25s cubic-bezier(0.4, 0, 0.2, 1)' : 'none',
          flexShrink: 0
        }}
      >
        <Sidebar
          currentPath={location.pathname}
          collapsed={isMobile ? false : collapsed}
          onToggleCollapse={() => setCollapsed((prev) => !prev)}
          mobileOpen={isMobile && mobileDrawerOpen}
          onCloseMobile={handleCloseMobile}
        />
      </div>

      {/* Main Content Area (Topbar + Scrollable View) */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          height: '100vh',
          minWidth: 0,
          overflow: 'hidden',
          backgroundColor: 'var(--bg-app, #0a0e1a)'
        }}
      >
        <TopBar
          onToggleSidebar={handleToggleSidebar}
          sidebarCollapsed={isMobile ? !mobileDrawerOpen : collapsed}
        />

        <main
          id="main-scroll-container"
          style={{
            flex: 1,
            overflowY: 'auto',
            overflowX: 'hidden',
            padding: isMobile ? '16px' : '24px',
            backgroundColor: 'var(--bg-app, #0a0e1a)',
            scrollbarWidth: 'thin'
          }}
        >
          <div
            style={{
              maxWidth: '1680px',
              margin: '0 auto',
              width: '100%'
            }}
          >
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};

export default AppLayout;
