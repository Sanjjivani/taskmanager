document.addEventListener('DOMContentLoaded', function() {
    // Auto-expand description textarea in add task form
    const descriptionInput = document.querySelector('.description-input');
    if (descriptionInput) {
        descriptionInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    }
    
    // Set default date to today if not set in add task form
    const dateInput = document.querySelector('.date-input');
    if (dateInput && !dateInput.value) {
        dateInput.value = new Date().toISOString().substr(0, 10);
    }

    // Toggle edit form
    document.querySelectorAll('.edit-btn').forEach(button => {
        button.addEventListener('click', function() {
            const taskId = this.getAttribute('data-task-id');
            const taskCard = document.getElementById(`task-card-${taskId}`);
            const displayView = taskCard.querySelector('.task-display');
            const editForm = taskCard.querySelector('.task-edit-form');
            displayView.style.display = 'none';
            editForm.style.display = 'block';
            
            // Auto-expand description textarea in edit form
            const editDescription = editForm.querySelector('.description-input');
            if (editDescription) {
                editDescription.style.height = 'auto';
                editDescription.style.height = (editDescription.scrollHeight) + 'px';
                editDescription.addEventListener('input', function() {
                    this.style.height = 'auto';
                    this.style.height = (editDescription.scrollHeight) + 'px';
                });
            }
        });
    });

    // Cancel edit
    document.querySelectorAll('.cancel-btn').forEach(button => {
        button.addEventListener('click', function() {
            const taskId = this.getAttribute('data-task-id');
            const taskCard = document.getElementById(`task-card-${taskId}`);
            const displayView = taskCard.querySelector('.task-display');
            const editForm = taskCard.querySelector('.task-edit-form');
            displayView.style.display = 'block';
            editForm.style.display = 'none';
        });
    });

    // Smooth scroll to task form on button click
    const addTaskButton = document.querySelector('.empty-state-button');
    if (addTaskButton) {
        addTaskButton.addEventListener('click', function(e) {
            e.preventDefault();
            const taskForm = document.querySelector('.task-form');
            taskForm.scrollIntoView({ behavior: 'smooth' });
            taskForm.querySelector('.task-title-input').focus();
        });
    }

    // Highlight overdue tasks
    const now = new Date();
    document.querySelectorAll('.task-due').forEach(due => {
        const dueDateText = due.textContent.trim();
        try {
            const dueDate = new Date(dueDateText);
            if (dueDate < now && !due.classList.contains('overdue')) {
                due.classList.add('overdue');
            }
        } catch (e) {
            console.error('Error parsing due date:', e);
        }
    });

    // Settings panel toggle
    const settingsToggle = document.getElementById('settings-toggle');
    const settingsPanel = document.getElementById('settings-panel');
    const settingsOverlay = document.getElementById('settings-overlay');
    const settingsClose = document.getElementById('settings-close');

    if (settingsToggle && settingsPanel && settingsOverlay && settingsClose) {
        settingsToggle.addEventListener('click', () => {
            settingsPanel.classList.toggle('open');
            settingsOverlay.classList.toggle('active');
        });

        settingsClose.addEventListener('click', () => {
            settingsPanel.classList.remove('open');
            settingsOverlay.classList.remove('active');
        });

        settingsOverlay.addEventListener('click', () => {
            settingsPanel.classList.remove('open');
            settingsOverlay.classList.remove('active');
        });
    }

    // Theme switching
    const themeButtons = document.querySelectorAll('.theme-option');
    themeButtons.forEach(button => {
        button.addEventListener('click', () => {
            const theme = button.getAttribute('data-theme');
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
        });
    });

    // Apply saved theme
    const savedTheme = localStorage.getItem('theme') || 'system';
    document.documentElement.setAttribute('data-theme', savedTheme);

    // Profile form confirmation
    const profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', function(e) {
            if (!confirm('Are you sure you want to update your profile details?')) {
                e.preventDefault();
            }
        });
    }

    // Pie chart for task progress
    const progressBtn = document.getElementById('view-progress-btn');
    const chartContainer = document.getElementById('progress-chart-container');
    let chartInstance = null;

    if (progressBtn && chartContainer) {
        progressBtn.addEventListener('click', () => {
            const isVisible = chartContainer.style.display === 'block';
            chartContainer.style.display = isVisible ? 'none' : 'block';

            if (!isVisible && !chartInstance) {
                // Fetch task progress data
                fetch('/task_progress')
                    .then(response => response.json())
                    .then(data => {
                        if (data.total === 0) {
                            chartContainer.innerHTML = '<p class="chart-empty">No tasks available to display progress.</p>';
                            return;
                        }

                        const ctx = document.getElementById('taskProgressChart').getContext('2d');
                        chartInstance = new Chart(ctx, {
                            type: 'pie',
                            data: {
                                labels: ['Completed', 'Incomplete'],
                                datasets: [{
                                    data: [data.completed, data.incomplete],
                                    backgroundColor: [
                                        getComputedStyle(document.documentElement).getPropertyValue('--success').trim(),
                                        getComputedStyle(document.documentElement).getPropertyValue('--primary').trim()
                                    ],
                                    borderColor: getComputedStyle(document.documentElement).getPropertyValue('--card-bg').trim(),
                                    borderWidth: 2
                                }]
                            },
                            options: {
                                responsive: true,
                                plugins: {
                                    legend: {
                                        position: 'top',
                                        labels: {
                                            color: getComputedStyle(document.documentElement).getPropertyValue('--text-primary').trim(),
                                            font: {
                                                size: 14,
                                                family: "'Inter', sans-serif"
                                            }
                                        }
                                    },
                                    tooltip: {
                                        backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--card-bg').trim(),
                                        titleColor: getComputedStyle(document.documentElement).getPropertyValue('--text-primary').trim(),
                                        bodyColor: getComputedStyle(document.documentElement).getPropertyValue('--text-primary').trim(),
                                        borderColor: getComputedStyle(document.documentElement).getPropertyValue('--border-color').trim(),
                                        borderWidth: 1
                                    }
                                },
                                animation: {
                                    animateScale: true,
                                    animateRotate: true
                                }
                            }
                        });
                    })
                    .catch(error => {
                        console.error('Error fetching task progress:', error);
                        chartContainer.innerHTML = '<p class="chart-empty">Error loading progress chart.</p>';
                    });
            }
        });
    }
});