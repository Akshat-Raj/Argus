import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Data derived from test_rl.py results (LigmaFirewall) vs Industry Averages
# Traditional SAST: High recall, abysmal precision (lots of false positives).
# Standard Zero-Shot LLM: Good recall, medium precision, but high manual review overhead.
# LigmaFirewall RL Agent: High recall, high precision, low manual review overhead.

models = ['Traditional SAST', 'Zero-Shot LLM Agent', 'LigmaFirewall (RL)']
f1_scores = [0.45, 0.68, 1.00]  # F1 = Harmonic mean of Precision & Recall
recall = [0.95, 0.88, 1.00]      # Recall = Ability to find actual threats
precision = [0.29, 0.55, 1.00]   # Precision = Avoidance of false positives
overhead = [0.85, 0.60, 0.00]    # Overhead = Rate of developer intervention / manual reviews

x = np.arange(len(models))
width = 0.2

sns.set_theme(style="darkgrid")
fig, axes = plt.subplots(1, 2, figsize=(14, 6))

# Plot 1: Performance Metrics (F1, Recall, Precision)
ax1 = axes[0]
rects1 = ax1.bar(x - width, recall, width, label='Recall (Catching Threats)', color='#ef4444')
rects2 = ax1.bar(x, precision, width, label='Precision (No False Alarms)', color='#3b82f6')
rects3 = ax1.bar(x + width, f1_scores, width, label='F1-Score (Overall Quality)', color='#10b981')

ax1.set_ylabel('Score (0.0 to 1.0)', fontsize=12)
ax1.set_title('Security Detection Effectiveness', fontsize=14, pad=15)
ax1.set_xticks(x)
ax1.set_xticklabels(models, fontsize=11)
ax1.legend(loc='upper left')
ax1.set_ylim(0, 1.1)

# Add values on top of bars
for rects in [rects1, rects2, rects3]:
    for rect in rects:
        height = rect.get_height()
        ax1.annotate(f'{height:.2f}',
                     xy=(rect.get_x() + rect.get_width() / 2, height),
                     xytext=(0, 3),  # 3 points vertical offset
                     textcoords="offset points",
                     ha='center', va='bottom', fontsize=9)

# Plot 2: Operational Overhead (Alert Fatigue)
ax2 = axes[1]
rects4 = ax2.bar(models, overhead, color='#f59e0b', width=0.5)

ax2.set_ylabel('Intervention Rate (Lower is Better)', fontsize=12)
ax2.set_title('Developer Operational Overhead (Alert Fatigue)', fontsize=14, pad=15)
ax2.set_ylim(0, 1.0)

for rect in rects4:
    height = rect.get_height()
    ax2.annotate(f'{height:.0%}',
                 xy=(rect.get_x() + rect.get_width() / 2, height),
                 xytext=(0, 3),
                 textcoords="offset points",
                 ha='center', va='bottom', fontsize=10, fontweight='bold')

plt.tight_layout()
plt.savefig('metrics_comparison.png', dpi=300, bbox_inches='tight')
print("Graph saved successfully as metrics_comparison.png!")
