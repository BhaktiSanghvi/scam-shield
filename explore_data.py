import pandas as pd

# Location of our dataset
file_path = "data/sms+spam+collection/SMSSpamCollection"

# Read the dataset
data = pd.read_csv(
    file_path,
    sep="\t",
    header=None,
    names=["label", "message"],
    encoding="utf-8"
)

# Display basic information
print("First 5 messages:")
print(data.head())

print("\nDataset shape:")
print(data.shape)

print("\nLabels:")
print(data["label"].value_counts())

print("\nMissing values:")
print(data.isnull().sum())

print("\nMessage length statistics:")
print(data["message"].str.len().describe()) 