' DocumentedComponent.vb - Visual Basic .NET z Atrybutem i Komentarzami XML
Imports System

' -------------------------------------------------------------------------
' 1. Definicja Niestandardowego Atrybutu (Custom Attribute)
' -------------------------------------------------------------------------

''' <summary>
''' Atrybut do oznaczania klas i metod związanych z zarządzaniem wersjami.
''' </summary>
''' <remarks>
''' Atrybut ten przechowuje informacje o numerze wersji komponentu oraz nazwisku autora.
''' </remarks>
<AttributeUsage(AttributeTargets.Class Or AttributeTargets.Method, AllowMultiple:=False)>
Public Class VersionInfoAttribute
    Inherits Attribute

    Private _version As String
    Private _author As String

    ''' <summary>
    ''' Inicjalizuje nową instancję atrybutu VersionInfo.
    ''' </summary>
    ''' <param name="version">Numer wersji (np. "1.0.0").</param>
    ''' <param name="author">Imię i nazwisko autora.</param>
    Public Sub New(ByVal version As String, ByVal author As String)
        Me._version = version
        Me._author = author
    End Sub

    ''' <summary>
    ''' Pobiera numer wersji.
    ''' </summary>
    Public ReadOnly Property Version() As String
        Get
            Return _version
        End Get
    End Property

    ''' <summary>
    ''' Pobiera nazwisko autora.
    ''' </summary>
    Public ReadOnly Property Author() As String
        Get
            Return _author
        End Get
    End Property
End Class

' -------------------------------------------------------------------------
' 2. Klasa z Zastosowaniem Atrybutu i Komentarzami XML
' -------------------------------------------------------------------------

''' <summary>
''' Komponent zarządzający transakcjami w systemie.
''' </summary>
''' <remarks>
''' Ta klasa symuluje kluczowe funkcje biznesowe i jest oznaczona atrybutem VersionInfo.
''' </remarks>
<VersionInfo("2.1.5", "Anna Kowalska")>
Public Class TransactionManager

    Private _transactionCounter As Integer = 0

    ''' <summary>
    ''' Pobiera bieżącą liczbę przetworzonych transakcji.
    ''' </summary>
    ''' <value>Liczba całkowita reprezentująca zliczone transakcje.</value>
    Public ReadOnly Property TransactionCount() As Integer
        Get
            Return _transactionCounter
        End Get
    End Property

    ''' <summary>
    ''' Symuluje rozpoczęcie nowej transakcji.
    ''' </summary>
    ''' <param name="amount">Kwota transakcji (w formacie Decimal).</param>
    ''' <returns>Wartość logiczna (Boolean) informująca o powodzeniu operacji.</returns>
    ''' <exception cref="ArgumentOutOfRangeException">Rzucany, gdy kwota jest ujemna.</exception>
    <VersionInfo("2.1.5.1", "Anna Kowalska")>
    Public Function StartNewTransaction(ByVal amount As Decimal) As Boolean
        If amount < 0 Then
            ' Rzucenie wyjątku z dokumentacją
            Throw New ArgumentOutOfRangeException(NameOf(amount), "Kwota transakcji nie może być ujemna.")
        End If

        Console.WriteLine($"Transakcja o wartości {amount:C} rozpoczęta.")
        _transactionCounter += 1
        Return True
    End Function

End Class

' -------------------------------------------------------------------------
' 3. Moduł testujący (demonstracja użycia refleksji do odczytu atrybutu)
' -------------------------------------------------------------------------
Module MainModule

    Sub Main()
        Console.WriteLine("=== Visual Basic .NET - Demo Atrybutów i XML Comments ===")

        ' 1. Testowanie klasy i metody
        Dim manager As New TransactionManager()
        manager.StartNewTransaction(150.75D)
        manager.StartNewTransaction(300.00D)

        Console.WriteLine($"Przetworzono transakcji: {manager.TransactionCount}")

        Console.WriteLine(Environment.NewLine & "--- Refleksja Atrybutu Klasy ---")

        ' 2. Refleksja: Pobieranie atrybutu klasy
        Dim classType As Type = GetType(TransactionManager)
        Dim classAttr As VersionInfoAttribute = TryCast( _
            Attribute.GetCustomAttribute(classType, GetType(VersionInfoAttribute)), _
            VersionInfoAttribute)

        If classAttr IsNot Nothing Then
            Console.WriteLine($"Klasa: {classType.Name}")
            Console.WriteLine($"Wersja Komponentu: {classAttr.Version}")
            Console.WriteLine($"Autor: {classAttr.Author}")
        End If

        Console.WriteLine(Environment.NewLine & "Naciśnij dowolny klawisz, aby zakończyć...")
        Console.ReadKey()

        ' UWAGA: Aby wygenerować dokumentację XML z tych komentarzy,
        ' należy w opcjach projektu Visual Studio włączyć "Generate XML documentation file".
    End Sub

End Module