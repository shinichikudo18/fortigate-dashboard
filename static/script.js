// Auto-refresh dashboard every 60 seconds
let refreshInterval;

function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        location.reload();
    }, 60000);
}

// Initialize tooltips and popovers
document.addEventListener('DOMContentLoaded', function() {
    // Auto-refresh is disabled to avoid disruption while viewing
    // Uncomment below to enable auto-refresh
    // startAutoRefresh();
    
    // Add click handlers for branch tabs to store active tab
    const tabButtons = document.querySelectorAll('#branchTabs button');
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            localStorage.setItem('activeTab', this.id);
        });
    });
    
    // Restore active tab on page load
    const activeTabId = localStorage.getItem('activeTab');
    if (activeTabId) {
        const tabButton = document.getElementById(activeTabId);
        if (tabButton) {
            const tab = new bootstrap.Tab(tabButton);
            tab.show();
        }
    }
});

// Function to format uptime
function formatUptime(timeticks) {
    if (!timeticks) return 'N/A';
    const ticks = parseInt(timeticks);
    const seconds = Math.floor(ticks / 100);
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
}
