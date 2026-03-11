document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('passwordInput');
    const strengthContainer = document.getElementById('strengthContainer');
    const scoreHeader = document.getElementById('scoreHeader');
    const strengthText = document.getElementById('strengthText');
    const strengthBar = document.getElementById('strengthBar');
    const scoreText = document.getElementById('scoreText');
    const crackTimeText = document.getElementById('crackTimeText');
    const suggestionsList = document.getElementById('suggestionsList');

    const STRENGTH_LEVELS = [
        { label: 'Very Weak', color: 'var(--danger)', bgClass: 'high', barWidth: '20%', barColor: '#ef4444' },
        { label: 'Weak', color: '#f97316', bgClass: 'high', barWidth: '40%', barColor: '#f97316' },
        { label: 'Medium', color: 'var(--warning)', bgClass: 'medium', barWidth: '60%', barColor: '#f59e0b' },
        { label: 'Strong', color: '#84cc16', bgClass: 'low', barWidth: '80%', barColor: '#84cc16' },
        { label: 'Very Strong', color: 'var(--success)', bgClass: 'low', barWidth: '100%', barColor: '#10b981' }
    ];

    passwordInput.addEventListener('input', (e) => {
        const password = e.target.value;
        
        if (!password) {
            strengthContainer.style.display = 'none';
            return;
        }

        strengthContainer.style.display = 'block';

        const result = zxcvbn(password);
        const score = result.score; 
        const levelConfig = STRENGTH_LEVELS[score];

        strengthText.textContent = levelConfig.label;
        strengthText.style.color = levelConfig.color;
        
        scoreText.textContent = `${score}/4`;
        crackTimeText.textContent = result.crack_times_display.offline_slow_hashing_1e4_per_second || 'Instant';
        
        scoreHeader.className = `score-header ${levelConfig.bgClass}`;
        
        strengthBar.style.width = levelConfig.barWidth;
        strengthBar.style.backgroundColor = levelConfig.barColor;
        
        suggestionsList.innerHTML = '';
        
        let messages = [];
        if (result.feedback.warning) {
            messages.push(result.feedback.warning);
        }
        if (result.feedback.suggestions && result.feedback.suggestions.length > 0) {
            messages = messages.concat(result.feedback.suggestions);
        }
        
        if (messages.length === 0 && score < 4) {
            messages.push('Add special characters, numbers, and uppercase letters.');
            messages.push('Avoid common patterns or predictable sequences.');
        }

        if (messages.length > 0) {
            messages.forEach(msg => {
                const tipItem = document.createElement('div');
                tipItem.className = 'tip-item';
                tipItem.innerHTML = `<div class="tip-icon">💡</div><div>${msg}</div>`;
                suggestionsList.appendChild(tipItem);
            });
            document.getElementById('suggestionsContainer').style.display = 'block';
        } else {
            document.getElementById('suggestionsContainer').style.display = 'none';
        }
    });
});
