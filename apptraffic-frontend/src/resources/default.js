export default {
    recordingModes: {
        metadata: "traffic metadata",
        decrypted: "decrypted https traffic",
        raw: "raw traffic (undecrypted)"
    },
    errorMessages: {
        pleaseContactAdmin: "Please contact the administrator.",
        serviceUnavailable: "The service is temporarily unavailable.  Please check your network connection.  If problem persists, please contact the administrator.",
        loginFailure: "The username or password is not recognised."
    },
    recordingStatuses: {
        creating: "creating the session",
        recording: "recording",
        ending: "ending the session",
        ended: "ended",
        creating_entry_hub: "creating entry hub",
        creating_exit_hub: "creating exit hub",
        created_entry_hub: "entryhub is created",
        error_creating_entry_hub: "error: entry hub not created",
        error_creating_exit_hub: "error: exit hub not created",
    },
    timeDifferenceText: function (from, to) {
        var timeDifference = to - from;
        timeDifference = timeDifference / 1000;
        var seconds = Math.floor(timeDifference % 60);
        timeDifference = timeDifference / 60;
        var minutes = Math.floor(timeDifference % 60);
        timeDifference = timeDifference / 60;
        var hours = Math.floor(timeDifference % 24);
        var days = Math.floor(timeDifference / 24);
        if (seconds < 0) seconds = 0;
        if (minutes < 0) minutes = 0;
        if (hours < 0) hours = 0;
        if (days < 0) days = 0;
        return [
            days.toString().padStart(2, "0"),
            hours.toString().padStart(2, "0"),
            minutes.toString().padStart(2, "0"),
            seconds.toString().padStart(2, "0"),
        ].join(":");
    },
    getDateText: function(date) {
        return date.toLocaleString();
    },
    humaniseText: function(text) {
        return text.charAt(0).toUpperCase() + text.slice(1)
    }
};

/*
    creating: "creating the session",
    recording: "recording",
    ending: "ending the session",
    ended: "session has ended",
    creating_entry_hub: "creating entry hub",
    creating_exit_hub: "creating exit hub",
    created_entry_hub: "entryhub is created",
    error_creating_entry_hub: "error: entry hub not created",
    error_creating_exit_hub : "error: exit hub not created",
*/