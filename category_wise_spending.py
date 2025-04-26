import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-GUI backend
import matplotlib.pyplot as plt

# Load the data
df = pd.read_excel("expenses.xlsx")

# Ensure Category and Month are strings and normalized
df['Category'] = df['Category'].astype(str).str.strip().str.lower()
df['Month'] = df['Month'].astype(str).str.strip()

# Group by Month and Category, summing the Amount
grouped = df.groupby(['Month', 'Category'])['Amount'].sum().unstack(fill_value=0)

# Create a bar chart
grouped.plot(kind='bar', figsize=(10, 6), width=0.8)
plt.title('Category-Wise Spending by Month')
plt.xlabel('Month')
plt.ylabel('Total Amount Spent')
plt.legend(title='Category')
plt.xticks(rotation=45)
plt.tight_layout()

# Save the plot to a file (for canvas display)
plt.savefig('category_spending_by_month.png')