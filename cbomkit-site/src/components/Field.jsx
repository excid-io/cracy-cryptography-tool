import { styles } from "../styles/styles";

/**
 * Reusable labeled input field.
 *
 * Used for Git URL, scan path, branch, commit, and PAT fields.
 */
export function Field({ label, value, onChange, placeholder, type = "text", theme }) {
  return (
    <label style={styles.field}>
      <span style={{ ...styles.label, color: theme.label }}>{label}</span>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
        style={{
          ...styles.input,
          background: theme.inputBg,
          color: theme.text,
          borderColor: theme.border,
        }}
      />
    </label>
  );
}