package io.vpv.net.model;

/**
 * Created by vprasanna on 4/4/18.
 */
public class CipherResponse {
    private String name;
    private String status;
    private String protocol;
    private String error;
    private boolean stop;
    public CipherResponse() {

    }
    public CipherResponse(String name, String status, String protocol, String error, boolean stop) {
        this.name = name;
        this.status = status;
        this.protocol = protocol;
        this.error = error;
        this.stop = stop;
    }

    /**
     * Gets name.
     *
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets name.
     *
     * @param name the name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets status.
     *
     * @return the status
     */
    public String getStatus() {
        return status;
    }

    /**
     * Sets status.
     *
     * @param status the status
     */
    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * Gets protocol.
     *
     * @return the protocol
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * Sets protocol.
     *
     * @param protocol the protocol
     */
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    /**
     * Gets error.
     *
     * @return the error
     */
    public String getError() {
        return error;
    }

    /**
     * Sets error.
     *
     * @param error the error
     */
    public void setError(String error) {
        this.error = error;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("CipherResponse{");
        sb.append("name='").append(name).append('\'');
        sb.append(", status='").append(status).append('\'');
        sb.append(", protocol='").append(protocol).append('\'');
        sb.append(", error='").append(error).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
