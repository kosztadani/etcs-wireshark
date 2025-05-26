package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.mdb;

import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common.EtcsMessage;
import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common.EtcsVariable;
import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common.EtcsVariableException;
import net.ucanaccess.jdbc.UcanaccessDriver;

import java.math.BigInteger;
import java.nio.file.Path;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;

/**
 * Utility to read messages from SUBSET-076-6-3 MDB files.
 */
public final class MdbReader
    implements AutoCloseable {

    private static final String CONNECTION_PREFIX = "jdbc:ucanaccess://";

    private static final String SQL = """
        select step.TCSOrder     step_id,
               step.ST_IO        message_direction,
               step.ST_INTERFACE message_interface,
               row.message_id    message_id,
               row.row_name      row_name,
               row.row_length    row_length,
               row.row_value     row_value
        from (select header.TCSOrder     step_id,
                     header.MessageOrder message_id,
                     header.Var_Row      row_id,
                     header.Var_Name     row_name,
                     header.Var_Len      row_length,
                     header.Var_Value    row_value,
                     1                   union_order
              from TSW_MessageHeader header
              union all
              select body.TCSOrder     step_id,
                     body.MessageOrder message_id,
                     body.Var_Row      row_id,
                     body.Var_Name     row_name,
                     body.Var_Len      row_length,
                     body.Var_Value    row_value,
                     2                 union_order
              from TSW_MessageBody body
              order by step_id, message_id, union_order, row_id) row
                 join TSW_TCStep step
                      on row.step_id = step.TCSOrder
        where step.ST_INTERFACE in ('LTM', 'BTM', 'RTM')
        """;

    private final Path mdbFile;

    private final Connection connection;

    private final String filename;

    /**
     * Creates a new reader.
     *
     * @param mdbFile The file to read messages from.
     * @throws SQLException if opening the file fails.
     */
    public MdbReader(final Path mdbFile) throws SQLException {
        this.mdbFile = mdbFile;
        this.connection = connect();
        this.filename = mdbFile.getFileName().toString();
    }

    private Connection connect() throws SQLException {
        UcanaccessDriver driver = new UcanaccessDriver();
        return driver.connect(connectionUrl(), new Properties());
    }

    private String connectionUrl() {
        return CONNECTION_PREFIX + mdbFile.toString();
    }

    /**
     * Reads messages from the underlying file.
     *
     * @return A sequence of messages
     * @throws SQLException if reading the database fails.
     */
    public List<MdbMessage> read() throws SQLException {
        List<MdbMessage> messages = new ArrayList<>();
        CallableStatement statement = connection.prepareCall(SQL);
        boolean hasResults = statement.execute();
        if (!hasResults) {
            System.out.println("WARNING: SQL query yielded no results.");
            System.out.println("-> ignoring file: " + filename);
            return Collections.emptyList();
        }
        try (ResultSet results = statement.getResultSet()) {
            List<EtcsVariable> variables = null;
            EtcsMessage etcsMessage;
            MdbMessage mdbMessage;
            MessageKey previousKey = null;
            String messageDirection;
            String messageInterface;
            while (results.next()) {
                int index = 1;
                int stepId = results.getInt(index++);
                messageDirection = results.getString(index++);
                messageInterface = results.getString(index++);
                int messageId = results.getInt(index++);
                String rowName = results.getString(index++);
                int rowLength = results.getInt(index++);
                String rowValue = results.getString(index++);
                MessageKey key = new MessageKey(stepId, messageId);
                if (!Objects.equals(key, previousKey)) {
                    previousKey = key;
                    variables = new ArrayList<>();
                    etcsMessage = new EtcsMessage(variables);
                    mdbMessage = new MdbMessage(
                        MessageInterface.valueOf(messageInterface),
                        MessageDirection.fromString(messageDirection),
                        etcsMessage,
                        String.format("%s: step %d, message %d", filename, stepId, messageId)
                    );
                    messages.add(mdbMessage);
                }
                Optional<EtcsVariable> variable = parseVariable(rowName, rowValue, rowLength);
                if (variable.isPresent()) {
                    variables.add(variable.get());
                } else {
                    System.out.println("WARNING: could not parse variable: " + rowName + " = \"" + rowValue + "\"");
                    System.out.println("-> ignoring file: " + filename);
                    return Collections.emptyList();
                }
            }
        }
        return messages;
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    private Optional<EtcsVariable> parseVariable(final String rowName, final String rowValue, final int rowLength) {
        EtcsVariable result = null;
        try {
            if (rowValue == null) {
                result = new EtcsVariable(rowLength, BigInteger.ZERO);
            } else if (rowName.equals("X_TEXT") && rowLength == 8) {
                result = EtcsVariable.fromCharacter(rowValue.charAt(0));
            } else if (rowValue.length() == 1 && rowLength != 8) {
                result = EtcsVariable.fromDecimalString(rowLength, rowValue);
            } else if (rowValue.length() > 1 || rowLength != 8) {
                if (rowValue.endsWith(" bcd")) {
                    result = EtcsVariable.fromHexString(rowLength, stripEnd(rowValue, 4));
                } else if (rowValue.endsWith(" d")) {
                    result = EtcsVariable.fromDecimalString(rowLength, stripEnd(rowValue, 2));
                } else if (rowValue.endsWith("d")) {
                    result = EtcsVariable.fromDecimalString(rowLength, stripEnd(rowValue, 1));
                } else if (rowValue.endsWith(" b")) {
                    result = EtcsVariable.fromBinaryString(rowLength, stripEnd(rowValue, 2));
                } else if (rowValue.endsWith("b")) {
                    result = EtcsVariable.fromBinaryString(rowLength, stripEnd(rowValue, 1));
                } else if (rowValue.endsWith(" h")) {
                    result = EtcsVariable.fromHexString(rowLength, stripEnd(rowValue, 2));
                } else if (rowValue.endsWith("h")) {
                    result = EtcsVariable.fromHexString(rowLength, stripEnd(rowValue, 1));
                }
            }
            if (result == null) {
                String stripped = removeSpaces(rowValue);
                if (rowLength == 4 * stripped.length()) {
                    result = EtcsVariable.fromHexString(rowLength, stripped);
                } else if (rowLength == stripped.length()) {
                    result = EtcsVariable.fromBinaryString(rowLength, stripped);
                } else {
                    result = EtcsVariable.fromDecimalString(rowLength, stripped);
                }
            }
        } catch (EtcsVariableException e) {
            return Optional.empty();
        }
        return Optional.of(result);
    }

    private String stripEnd(final String value, final int charactersToStrip) {
        return value.substring(0, value.length() - charactersToStrip);

    }

    private String removeSpaces(final String value) {
        return value.replaceAll("\\s+", "");
    }

    @Override
    public void close() throws Exception {
        connection.close();
    }

    private record MessageKey(int stepId, int messageId) {

    }
}
