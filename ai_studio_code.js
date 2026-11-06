rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }

    function isValidId(id) {
      return id is string && id.size() > 0 && id.size() <= 128 && id.matches('^[a-zA-Z0-9_\\-]+$');
    }

    function isSignedIn() {
      return request.auth != null;
    }

    function isOwner(userId) {
      return isSignedIn() && request.auth.uid == userId;
    }

    function isAdmin() {
      return isSignedIn() && (
        exists(/databases/$(database)/documents/admins/$(request.auth.uid)) ||
        (exists(/databases/$(database)/documents/users/$(request.auth.uid)) &&
         get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin') ||
        request.auth.token.email == 'charanrajc888@gmail.com'
      );
    }

    function isStaff() {
      return isSignedIn() && (
        isAdmin() ||
        exists(/databases/$(database)/documents/staff/$(request.auth.uid)) ||
        (exists(/databases/$(database)/documents/users/$(request.auth.uid)) &&
         get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'staff')
      );
    }

    match /users/{userId} {
      allow get: if isOwner(userId) || isAdmin() || isStaff();
      allow list: if isAdmin();
      allow create: if isSignedIn() && isOwner(userId);
      allow update: if isOwner(userId) || isAdmin();
      allow delete: if isAdmin();
    }

    match /events/{eventId} {
      allow get, list: if true;
      allow create, update, delete: if isAdmin();
    }

    match /bookings/{bookingId} {
      allow get: if isSignedIn() && (resource.data.userId == request.auth.uid || isAdmin() || isStaff());
      allow list: if isSignedIn() && (resource.data.userId == request.auth.uid || isAdmin());
      allow create: if isSignedIn();
      allow update: if isAdmin();
      allow delete: if isAdmin();
    }

    match /tickets/{ticketId} {
      allow get: if isSignedIn();
      allow list: if isSignedIn() && (isAdmin() || isStaff());
      allow create: if isSignedIn();
      allow update: if isStaff() || isAdmin();
      allow delete: if isAdmin();
    }
  }
}