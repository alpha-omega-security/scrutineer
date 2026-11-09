import React, {useEffect, useState} from 'react';
import {Text, View} from 'react-native';

const API = 'https://notes.example.test';

export default function App({token}) {
  const [notes, setNotes] = useState([]);
  useEffect(() => {
    fetch(`${API}/notes`, {headers: {Authorization: `Bearer ${token}`}})
      .then(r => r.json())
      .then(setNotes);
  }, [token]);
  return (
    <View>
      {notes.map(n => (
        <Text key={n.id}>{n.title}</Text>
      ))}
    </View>
  );
}
