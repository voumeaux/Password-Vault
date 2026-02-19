import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;
// actual app
public class VaultApp {
    private JFrame frame;
    private JTextField pinField;
    private JTextField labelField;
    private JTextField userField;
    private JTextField passField;
    private JTextArea vaultDisplay;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new VaultApp().showLoginScreen());

    }

    public String PWGen() {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        int length = 12; // You can change this to any desired length
        StringBuilder password = new StringBuilder();
        java.util.Random random = new java.util.Random();

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            password.append(characters.charAt(index));
        }

        return password.toString();
    }

    private void showLoginScreen() {
        frame = new JFrame("Password Vault - Login");
        frame.setTitle("PVault");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(300, 150);
        frame.setLayout(new FlowLayout());

        JLabel pinLabel = new JLabel("Enter PIN:");
        pinField = new JTextField(10);
        JButton loginButton = new JButton("Login");

        loginButton.addActionListener(this::handleLogin);

        frame.add(pinLabel);
        frame.add(pinField);
        frame.add(loginButton);
        frame.setVisible(true);
    }

    private void handleLogin(ActionEvent e) {
        int enteredPin;
        try {
            enteredPin = Integer.parseInt(pinField.getText());
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(frame, "PIN must be a number.");
            return;
        }

        Login login = new Login();
        if (login.enterPW(enteredPin)) {

            frame.dispose();
            showVaultScreen(enteredPin);
        } else {
            JOptionPane.showMessageDialog(frame, "Wrong PIN.");
        }
    }

    private void showVaultScreen(int pin) {
        Storage storage = new Storage(pin);

        frame = new JFrame("Password Vault");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 400);
        frame.setLayout(new BorderLayout());

        JPanel inputPanel = new JPanel(new GridLayout(4, 2));
        labelField = new JTextField();
        userField = new JTextField();
        passField = new JTextField();

        JButton saveButton = new JButton("Save Entry");
        JButton PasswordGen = new JButton("Generate A Password");
        JButton deleteButton = new JButton("Delete an Entry");

        inputPanel.add(new JLabel("Label:"));
        inputPanel.add(labelField);
        inputPanel.add(new JLabel("Username:"));
        inputPanel.add(userField);
        inputPanel.add(new JLabel("Password:"));
        inputPanel.add(passField);
        inputPanel.add(new JLabel(""));
        inputPanel.add(saveButton);
        inputPanel.add(new JLabel(""));
        inputPanel.add(PasswordGen);
        inputPanel.add(new JLabel(""));
        inputPanel.add(deleteButton);


        vaultDisplay = new JTextArea();
        vaultDisplay.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(vaultDisplay);

        PasswordGen.addActionListener(ae -> {
            JFrame passwordFrame = new JFrame("Password");
            passwordFrame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
            passwordFrame.setSize(300, 150);
            passwordFrame.setLayout(new FlowLayout());

            JTextArea textArea = new JTextArea(3, 20);
            textArea.setEditable(false);
            textArea.append(PWGen());

            passwordFrame.add(textArea);
            passwordFrame.setVisible(true);
        });


        saveButton.addActionListener(ae -> {
            String label = labelField.getText();
            String user = userField.getText();
            String pass = passField.getText();
            if (!label.isEmpty() && !user.isEmpty() && !pass.isEmpty()) {
                storage.saveEntry(label, user, pass);
                updateVaultDisplay(storage);
                labelField.setText("");
                userField.setText("");
                passField.setText("");
            }
        });

        deleteButton.addActionListener(ae -> {
            String label = labelField.getText();
            if (!label.isEmpty()) {
                int confirm = JOptionPane.showConfirmDialog(frame,
                        "Are you sure you want to delete the entry for label: " + label + "?",
                        "Confirm Delete", JOptionPane.YES_NO_OPTION);
                if (confirm == JOptionPane.YES_OPTION) {
                    storage.deleteEntry(label);
                    updateVaultDisplay(storage);
                    labelField.setText("");
                    userField.setText("");
                    passField.setText("");
                }
            } else {
                JOptionPane.showMessageDialog(frame, "Please enter a label to delete.");
            }
        });


        frame.add(inputPanel, BorderLayout.NORTH);
        frame.add(scrollPane, BorderLayout.CENTER);
        updateVaultDisplay(storage);
        frame.setVisible(true);
    }

    private void updateVaultDisplay(Storage storage) {
        List<String> entries = storage.loadEntries();
        vaultDisplay.setText("");
        for (String entry : entries) {
            vaultDisplay.append(entry + "\n");
        }
    }
}
